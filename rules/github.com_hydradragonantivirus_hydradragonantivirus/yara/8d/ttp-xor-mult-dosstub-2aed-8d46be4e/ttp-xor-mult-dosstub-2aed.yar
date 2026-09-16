rule TTP_XOR_MULT_DOSStub_2aed {
  strings:
    $key_2aed = { 7e 85 [2] 0a 9d [2] 4d 9f [2] 0a 8e [2] 44 82 [2] 48 88 [2] 5f 83 [2] 44 cd [2] 79 }

  condition:
    any of them
}
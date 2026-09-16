rule TTP_XOR_MULT_DOSStub_7aed {
  strings:
    $key_7aed = { 2e 85 [2] 5a 9d [2] 1d 9f [2] 5a 8e [2] 14 82 [2] 18 88 [2] 0f 83 [2] 14 cd [2] 29 }

  condition:
    any of them
}
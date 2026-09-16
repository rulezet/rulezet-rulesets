rule TTP_XOR_MULT_DOSStub_2ded {
  strings:
    $key_2ded = { 79 85 [2] 0d 9d [2] 4a 9f [2] 0d 8e [2] 43 82 [2] 4f 88 [2] 58 83 [2] 43 cd [2] 7e }

  condition:
    any of them
}
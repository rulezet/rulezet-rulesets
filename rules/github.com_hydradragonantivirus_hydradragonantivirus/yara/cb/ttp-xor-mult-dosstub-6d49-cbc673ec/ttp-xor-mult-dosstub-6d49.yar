rule TTP_XOR_MULT_DOSStub_6d49 {
  strings:
    $key_6d49 = { 39 21 [2] 4d 39 [2] 0a 3b [2] 4d 2a [2] 03 26 [2] 0f 2c [2] 18 27 [2] 03 69 [2] 3e }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_6d44 {
  strings:
    $key_6d44 = { 39 2c [2] 4d 34 [2] 0a 36 [2] 4d 27 [2] 03 2b [2] 0f 21 [2] 18 2a [2] 03 64 [2] 3e }

  condition:
    any of them
}
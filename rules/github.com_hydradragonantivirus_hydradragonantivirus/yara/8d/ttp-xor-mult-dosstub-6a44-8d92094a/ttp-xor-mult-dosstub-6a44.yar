rule TTP_XOR_MULT_DOSStub_6a44 {
  strings:
    $key_6a44 = { 3e 2c [2] 4a 34 [2] 0d 36 [2] 4a 27 [2] 04 2b [2] 08 21 [2] 1f 2a [2] 04 64 [2] 39 }

  condition:
    any of them
}
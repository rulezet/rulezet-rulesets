rule TTP_XOR_MULT_DOSStub_3742 {
  strings:
    $key_3742 = { 63 2a [2] 17 32 [2] 50 30 [2] 17 21 [2] 59 2d [2] 55 27 [2] 42 2c [2] 59 62 [2] 64 }

  condition:
    any of them
}
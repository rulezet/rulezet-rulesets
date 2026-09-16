rule TTP_XOR_MULT_DOSStub_4042 {
  strings:
    $key_4042 = { 14 2a [2] 60 32 [2] 27 30 [2] 60 21 [2] 2e 2d [2] 22 27 [2] 35 2c [2] 2e 62 [2] 13 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_c9d0 {
  strings:
    $key_c9d0 = { 9d b8 [2] e9 a0 [2] ae a2 [2] e9 b3 [2] a7 bf [2] ab b5 [2] bc be [2] a7 f0 [2] 9a }

  condition:
    any of them
}
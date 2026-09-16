rule TTP_XOR_MULT_DOSStub_3143 {
  strings:
    $key_3143 = { 65 2b [2] 11 33 [2] 56 31 [2] 11 20 [2] 5f 2c [2] 53 26 [2] 44 2d [2] 5f 63 [2] 62 }

  condition:
    any of them
}
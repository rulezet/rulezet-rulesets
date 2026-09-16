rule TTP_XOR_MULT_DOSStub_33b2 {
  strings:
    $key_33b2 = { 67 da [2] 13 c2 [2] 54 c0 [2] 13 d1 [2] 5d dd [2] 51 d7 [2] 46 dc [2] 5d 92 [2] 60 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_72b2 {
  strings:
    $key_72b2 = { 26 da [2] 52 c2 [2] 15 c0 [2] 52 d1 [2] 1c dd [2] 10 d7 [2] 07 dc [2] 1c 92 [2] 21 }

  condition:
    any of them
}
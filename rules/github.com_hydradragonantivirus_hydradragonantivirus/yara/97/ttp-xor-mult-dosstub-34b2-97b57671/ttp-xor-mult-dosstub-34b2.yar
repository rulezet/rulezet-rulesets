rule TTP_XOR_MULT_DOSStub_34b2 {
  strings:
    $key_34b2 = { 60 da [2] 14 c2 [2] 53 c0 [2] 14 d1 [2] 5a dd [2] 56 d7 [2] 41 dc [2] 5a 92 [2] 67 }

  condition:
    any of them
}
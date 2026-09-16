rule TTP_XOR_MULT_DOSStub_11b2 {
  strings:
    $key_11b2 = { 45 da [2] 31 c2 [2] 76 c0 [2] 31 d1 [2] 7f dd [2] 73 d7 [2] 64 dc [2] 7f 92 [2] 42 }

  condition:
    any of them
}
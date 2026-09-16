rule TTP_XOR_MULT_DOSStub_eab9 {
  strings:
    $key_eab9 = { be d1 [2] ca c9 [2] 8d cb [2] ca da [2] 84 d6 [2] 88 dc [2] 9f d7 [2] 84 99 [2] b9 }

  condition:
    any of them
}
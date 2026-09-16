rule TTP_XOR_MULT_DOSStub_eab1 {
  strings:
    $key_eab1 = { be d9 [2] ca c1 [2] 8d c3 [2] ca d2 [2] 84 de [2] 88 d4 [2] 9f df [2] 84 91 [2] b9 }

  condition:
    any of them
}
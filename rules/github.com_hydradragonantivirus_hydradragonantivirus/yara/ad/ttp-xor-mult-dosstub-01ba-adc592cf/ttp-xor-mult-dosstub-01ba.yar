rule TTP_XOR_MULT_DOSStub_01ba {
  strings:
    $key_01ba = { 55 d2 [2] 21 ca [2] 66 c8 [2] 21 d9 [2] 6f d5 [2] 63 df [2] 74 d4 [2] 6f 9a [2] 52 }

  condition:
    any of them
}
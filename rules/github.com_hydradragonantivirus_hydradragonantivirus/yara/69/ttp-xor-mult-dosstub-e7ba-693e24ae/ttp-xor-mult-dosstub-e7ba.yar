rule TTP_XOR_MULT_DOSStub_e7ba {
  strings:
    $key_e7ba = { b3 d2 [2] c7 ca [2] 80 c8 [2] c7 d9 [2] 89 d5 [2] 85 df [2] 92 d4 [2] 89 9a [2] b4 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_74ba {
  strings:
    $key_74ba = { 20 d2 [2] 54 ca [2] 13 c8 [2] 54 d9 [2] 1a d5 [2] 16 df [2] 01 d4 [2] 1a 9a [2] 27 }

  condition:
    any of them
}
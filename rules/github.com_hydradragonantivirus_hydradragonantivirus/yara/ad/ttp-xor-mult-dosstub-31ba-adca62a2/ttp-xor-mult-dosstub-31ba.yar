rule TTP_XOR_MULT_DOSStub_31ba {
  strings:
    $key_31ba = { 65 d2 [2] 11 ca [2] 56 c8 [2] 11 d9 [2] 5f d5 [2] 53 df [2] 44 d4 [2] 5f 9a [2] 62 }

  condition:
    any of them
}
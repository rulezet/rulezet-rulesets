rule TTP_XOR_MULT_DOSStub_54ba {
  strings:
    $key_54ba = { 00 d2 [2] 74 ca [2] 33 c8 [2] 74 d9 [2] 3a d5 [2] 36 df [2] 21 d4 [2] 3a 9a [2] 07 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_22ba {
  strings:
    $key_22ba = { 76 d2 [2] 02 ca [2] 45 c8 [2] 02 d9 [2] 4c d5 [2] 40 df [2] 57 d4 [2] 4c 9a [2] 71 }

  condition:
    any of them
}
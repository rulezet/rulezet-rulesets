rule TTP_XOR_MULT_DOSStub_18ba {
  strings:
    $key_18ba = { 4c d2 [2] 38 ca [2] 7f c8 [2] 38 d9 [2] 76 d5 [2] 7a df [2] 6d d4 [2] 76 9a [2] 4b }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_47ba {
  strings:
    $key_47ba = { 13 d2 [2] 67 ca [2] 20 c8 [2] 67 d9 [2] 29 d5 [2] 25 df [2] 32 d4 [2] 29 9a [2] 14 }

  condition:
    any of them
}
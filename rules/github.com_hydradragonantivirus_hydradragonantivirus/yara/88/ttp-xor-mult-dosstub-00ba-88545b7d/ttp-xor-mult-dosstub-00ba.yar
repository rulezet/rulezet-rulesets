rule TTP_XOR_MULT_DOSStub_00ba {
  strings:
    $key_00ba = { 54 d2 [2] 20 ca [2] 67 c8 [2] 20 d9 [2] 6e d5 [2] 62 df [2] 75 d4 [2] 6e 9a [2] 53 }

  condition:
    any of them
}
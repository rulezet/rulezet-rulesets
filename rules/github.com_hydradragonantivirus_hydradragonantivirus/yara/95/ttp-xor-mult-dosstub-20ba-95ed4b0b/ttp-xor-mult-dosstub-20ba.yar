rule TTP_XOR_MULT_DOSStub_20ba {
  strings:
    $key_20ba = { 74 d2 [2] 00 ca [2] 47 c8 [2] 00 d9 [2] 4e d5 [2] 42 df [2] 55 d4 [2] 4e 9a [2] 73 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_bae6 {
  strings:
    $key_bae6 = { ee 8e [2] 9a 96 [2] dd 94 [2] 9a 85 [2] d4 89 [2] d8 83 [2] cf 88 [2] d4 c6 [2] e9 }

  condition:
    any of them
}
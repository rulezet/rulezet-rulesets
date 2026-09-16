rule TTP_XOR_MULT_DOSStub_ba70 {
  strings:
    $key_ba70 = { ee 18 [2] 9a 00 [2] dd 02 [2] 9a 13 [2] d4 1f [2] d8 15 [2] cf 1e [2] d4 50 [2] e9 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_ba66 {
  strings:
    $key_ba66 = { ee 0e [2] 9a 16 [2] dd 14 [2] 9a 05 [2] d4 09 [2] d8 03 [2] cf 08 [2] d4 46 [2] e9 }

  condition:
    any of them
}
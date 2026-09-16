rule TTP_XOR_MULT_DOSStub_ba77 {
  strings:
    $key_ba77 = { ee 1f [2] 9a 07 [2] dd 05 [2] 9a 14 [2] d4 18 [2] d8 12 [2] cf 19 [2] d4 57 [2] e9 }

  condition:
    any of them
}
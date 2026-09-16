rule TTP_XOR_MULT_DOSStub_ba57 {
  strings:
    $key_ba57 = { ee 3f [2] 9a 27 [2] dd 25 [2] 9a 34 [2] d4 38 [2] d8 32 [2] cf 39 [2] d4 77 [2] e9 }

  condition:
    any of them
}
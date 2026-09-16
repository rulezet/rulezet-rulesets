rule TTP_XOR_MULT_DOSStub_ba47 {
  strings:
    $key_ba47 = { ee 2f [2] 9a 37 [2] dd 35 [2] 9a 24 [2] d4 28 [2] d8 22 [2] cf 29 [2] d4 67 [2] e9 }

  condition:
    any of them
}
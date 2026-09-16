rule TTP_XOR_MULT_DOSStub_ba17 {
  strings:
    $key_ba17 = { ee 7f [2] 9a 67 [2] dd 65 [2] 9a 74 [2] d4 78 [2] d8 72 [2] cf 79 [2] d4 37 [2] e9 }

  condition:
    any of them
}
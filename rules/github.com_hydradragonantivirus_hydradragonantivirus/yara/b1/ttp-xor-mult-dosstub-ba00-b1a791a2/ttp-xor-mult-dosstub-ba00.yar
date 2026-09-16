rule TTP_XOR_MULT_DOSStub_ba00 {
  strings:
    $key_ba00 = { ee 68 [2] 9a 70 [2] dd 72 [2] 9a 63 [2] d4 6f [2] d8 65 [2] cf 6e [2] d4 20 [2] e9 }

  condition:
    any of them
}
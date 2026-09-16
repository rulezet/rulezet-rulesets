rule TTP_XOR_MULT_DOSStub_ba11 {
  strings:
    $key_ba11 = { ee 79 [2] 9a 61 [2] dd 63 [2] 9a 72 [2] d4 7e [2] d8 74 [2] cf 7f [2] d4 31 [2] e9 }

  condition:
    any of them
}
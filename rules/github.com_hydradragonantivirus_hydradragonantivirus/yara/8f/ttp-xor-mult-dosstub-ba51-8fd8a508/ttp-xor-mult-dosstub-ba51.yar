rule TTP_XOR_MULT_DOSStub_ba51 {
  strings:
    $key_ba51 = { ee 39 [2] 9a 21 [2] dd 23 [2] 9a 32 [2] d4 3e [2] d8 34 [2] cf 3f [2] d4 71 [2] e9 }

  condition:
    any of them
}
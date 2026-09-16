rule TTP_XOR_MULT_DOSStub_baf6 {
  strings:
    $key_baf6 = { ee 9e [2] 9a 86 [2] dd 84 [2] 9a 95 [2] d4 99 [2] d8 93 [2] cf 98 [2] d4 d6 [2] e9 }

  condition:
    any of them
}
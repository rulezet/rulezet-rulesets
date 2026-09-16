rule TTP_XOR_MULT_DOSStub_baf1 {
  strings:
    $key_baf1 = { ee 99 [2] 9a 81 [2] dd 83 [2] 9a 92 [2] d4 9e [2] d8 94 [2] cf 9f [2] d4 d1 [2] e9 }

  condition:
    any of them
}
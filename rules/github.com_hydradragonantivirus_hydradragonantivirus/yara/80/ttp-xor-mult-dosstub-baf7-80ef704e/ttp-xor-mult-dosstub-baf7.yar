rule TTP_XOR_MULT_DOSStub_baf7 {
  strings:
    $key_baf7 = { ee 9f [2] 9a 87 [2] dd 85 [2] 9a 94 [2] d4 98 [2] d8 92 [2] cf 99 [2] d4 d7 [2] e9 }

  condition:
    any of them
}
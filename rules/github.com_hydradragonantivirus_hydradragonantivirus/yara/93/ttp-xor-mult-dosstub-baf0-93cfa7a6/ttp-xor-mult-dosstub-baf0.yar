rule TTP_XOR_MULT_DOSStub_baf0 {
  strings:
    $key_baf0 = { ee 98 [2] 9a 80 [2] dd 82 [2] 9a 93 [2] d4 9f [2] d8 95 [2] cf 9e [2] d4 d0 [2] e9 }

  condition:
    any of them
}
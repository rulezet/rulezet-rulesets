rule TTP_XOR_MULT_DOSStub_ba10 {
  strings:
    $key_ba10 = { ee 78 [2] 9a 60 [2] dd 62 [2] 9a 73 [2] d4 7f [2] d8 75 [2] cf 7e [2] d4 30 [2] e9 }

  condition:
    any of them
}
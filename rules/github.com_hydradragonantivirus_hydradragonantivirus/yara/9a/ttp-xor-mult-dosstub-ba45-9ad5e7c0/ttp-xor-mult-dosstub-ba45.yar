rule TTP_XOR_MULT_DOSStub_ba45 {
  strings:
    $key_ba45 = { ee 2d [2] 9a 35 [2] dd 37 [2] 9a 26 [2] d4 2a [2] d8 20 [2] cf 2b [2] d4 65 [2] e9 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_ba48 {
  strings:
    $key_ba48 = { ee 20 [2] 9a 38 [2] dd 3a [2] 9a 2b [2] d4 27 [2] d8 2d [2] cf 26 [2] d4 68 [2] e9 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_ba72 {
  strings:
    $key_ba72 = { ee 1a [2] 9a 02 [2] dd 00 [2] 9a 11 [2] d4 1d [2] d8 17 [2] cf 1c [2] d4 52 [2] e9 }

  condition:
    any of them
}
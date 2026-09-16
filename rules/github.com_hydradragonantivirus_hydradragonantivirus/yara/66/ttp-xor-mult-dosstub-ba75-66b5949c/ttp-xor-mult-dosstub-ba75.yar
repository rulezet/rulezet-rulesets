rule TTP_XOR_MULT_DOSStub_ba75 {
  strings:
    $key_ba75 = { ee 1d [2] 9a 05 [2] dd 07 [2] 9a 16 [2] d4 1a [2] d8 10 [2] cf 1b [2] d4 55 [2] e9 }

  condition:
    any of them
}
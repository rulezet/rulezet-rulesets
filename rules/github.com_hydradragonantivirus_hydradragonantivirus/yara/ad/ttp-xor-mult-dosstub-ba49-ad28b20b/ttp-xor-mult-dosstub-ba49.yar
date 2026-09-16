rule TTP_XOR_MULT_DOSStub_ba49 {
  strings:
    $key_ba49 = { ee 21 [2] 9a 39 [2] dd 3b [2] 9a 2a [2] d4 26 [2] d8 2c [2] cf 27 [2] d4 69 [2] e9 }

  condition:
    any of them
}
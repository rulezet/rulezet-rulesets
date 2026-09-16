rule TTP_XOR_MULT_DOSStub_ba18 {
  strings:
    $key_ba18 = { ee 70 [2] 9a 68 [2] dd 6a [2] 9a 7b [2] d4 77 [2] d8 7d [2] cf 76 [2] d4 38 [2] e9 }

  condition:
    any of them
}
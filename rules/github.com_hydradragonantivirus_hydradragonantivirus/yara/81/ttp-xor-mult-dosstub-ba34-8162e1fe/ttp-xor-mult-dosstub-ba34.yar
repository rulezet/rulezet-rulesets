rule TTP_XOR_MULT_DOSStub_ba34 {
  strings:
    $key_ba34 = { ee 5c [2] 9a 44 [2] dd 46 [2] 9a 57 [2] d4 5b [2] d8 51 [2] cf 5a [2] d4 14 [2] e9 }

  condition:
    any of them
}
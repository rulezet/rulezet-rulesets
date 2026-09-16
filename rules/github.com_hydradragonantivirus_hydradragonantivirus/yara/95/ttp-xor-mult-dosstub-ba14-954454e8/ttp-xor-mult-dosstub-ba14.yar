rule TTP_XOR_MULT_DOSStub_ba14 {
  strings:
    $key_ba14 = { ee 7c [2] 9a 64 [2] dd 66 [2] 9a 77 [2] d4 7b [2] d8 71 [2] cf 7a [2] d4 34 [2] e9 }

  condition:
    any of them
}
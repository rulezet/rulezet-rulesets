rule TTP_XOR_MULT_DOSStub_ba59 {
  strings:
    $key_ba59 = { ee 31 [2] 9a 29 [2] dd 2b [2] 9a 3a [2] d4 36 [2] d8 3c [2] cf 37 [2] d4 79 [2] e9 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_ba24 {
  strings:
    $key_ba24 = { ee 4c [2] 9a 54 [2] dd 56 [2] 9a 47 [2] d4 4b [2] d8 41 [2] cf 4a [2] d4 04 [2] e9 }

  condition:
    any of them
}
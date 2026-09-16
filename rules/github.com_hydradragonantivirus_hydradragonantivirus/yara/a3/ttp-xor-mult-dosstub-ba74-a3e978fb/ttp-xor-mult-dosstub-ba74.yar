rule TTP_XOR_MULT_DOSStub_ba74 {
  strings:
    $key_ba74 = { ee 1c [2] 9a 04 [2] dd 06 [2] 9a 17 [2] d4 1b [2] d8 11 [2] cf 1a [2] d4 54 [2] e9 }

  condition:
    any of them
}
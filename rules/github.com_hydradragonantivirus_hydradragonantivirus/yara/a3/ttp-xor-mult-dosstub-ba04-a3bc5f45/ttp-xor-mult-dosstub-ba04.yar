rule TTP_XOR_MULT_DOSStub_ba04 {
  strings:
    $key_ba04 = { ee 6c [2] 9a 74 [2] dd 76 [2] 9a 67 [2] d4 6b [2] d8 61 [2] cf 6a [2] d4 24 [2] e9 }

  condition:
    any of them
}
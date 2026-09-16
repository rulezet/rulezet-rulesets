rule TTP_XOR_MULT_DOSStub_bae9 {
  strings:
    $key_bae9 = { ee 81 [2] 9a 99 [2] dd 9b [2] 9a 8a [2] d4 86 [2] d8 8c [2] cf 87 [2] d4 c9 [2] e9 }

  condition:
    any of them
}
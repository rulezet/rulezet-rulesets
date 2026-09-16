rule TTP_XOR_MULT_DOSStub_bae8 {
  strings:
    $key_bae8 = { ee 80 [2] 9a 98 [2] dd 9a [2] 9a 8b [2] d4 87 [2] d8 8d [2] cf 86 [2] d4 c8 [2] e9 }

  condition:
    any of them
}
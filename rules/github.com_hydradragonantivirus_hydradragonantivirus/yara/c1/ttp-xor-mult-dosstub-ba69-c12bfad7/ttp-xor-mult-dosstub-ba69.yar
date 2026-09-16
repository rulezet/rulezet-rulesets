rule TTP_XOR_MULT_DOSStub_ba69 {
  strings:
    $key_ba69 = { ee 01 [2] 9a 19 [2] dd 1b [2] 9a 0a [2] d4 06 [2] d8 0c [2] cf 07 [2] d4 49 [2] e9 }

  condition:
    any of them
}
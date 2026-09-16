rule TTP_XOR_MULT_DOSStub_ba25 {
  strings:
    $key_ba25 = { ee 4d [2] 9a 55 [2] dd 57 [2] 9a 46 [2] d4 4a [2] d8 40 [2] cf 4b [2] d4 05 [2] e9 }

  condition:
    any of them
}
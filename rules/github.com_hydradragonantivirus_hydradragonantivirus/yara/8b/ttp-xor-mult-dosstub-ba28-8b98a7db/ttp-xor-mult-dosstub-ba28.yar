rule TTP_XOR_MULT_DOSStub_ba28 {
  strings:
    $key_ba28 = { ee 40 [2] 9a 58 [2] dd 5a [2] 9a 4b [2] d4 47 [2] d8 4d [2] cf 46 [2] d4 08 [2] e9 }

  condition:
    any of them
}
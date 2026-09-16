rule TTP_XOR_MULT_DOSStub_ba29 {
  strings:
    $key_ba29 = { ee 41 [2] 9a 59 [2] dd 5b [2] 9a 4a [2] d4 46 [2] d8 4c [2] cf 47 [2] d4 09 [2] e9 }

  condition:
    any of them
}
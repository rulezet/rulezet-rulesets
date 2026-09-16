rule TTP_XOR_MULT_DOSStub_ba39 {
  strings:
    $key_ba39 = { ee 51 [2] 9a 49 [2] dd 4b [2] 9a 5a [2] d4 56 [2] d8 5c [2] cf 57 [2] d4 19 [2] e9 }

  condition:
    any of them
}
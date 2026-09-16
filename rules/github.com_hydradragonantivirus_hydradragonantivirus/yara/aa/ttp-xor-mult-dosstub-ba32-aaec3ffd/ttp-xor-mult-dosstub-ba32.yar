rule TTP_XOR_MULT_DOSStub_ba32 {
  strings:
    $key_ba32 = { ee 5a [2] 9a 42 [2] dd 40 [2] 9a 51 [2] d4 5d [2] d8 57 [2] cf 5c [2] d4 12 [2] e9 }

  condition:
    any of them
}
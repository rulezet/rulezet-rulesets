rule TTP_XOR_MULT_DOSStub_ba22 {
  strings:
    $key_ba22 = { ee 4a [2] 9a 52 [2] dd 50 [2] 9a 41 [2] d4 4d [2] d8 47 [2] cf 4c [2] d4 02 [2] e9 }

  condition:
    any of them
}
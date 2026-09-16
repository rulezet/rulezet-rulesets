rule TTP_XOR_MULT_DOSStub_ba5a {
  strings:
    $key_ba5a = { ee 32 [2] 9a 2a [2] dd 28 [2] 9a 39 [2] d4 35 [2] d8 3f [2] cf 34 [2] d4 7a [2] e9 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_ba1a {
  strings:
    $key_ba1a = { ee 72 [2] 9a 6a [2] dd 68 [2] 9a 79 [2] d4 75 [2] d8 7f [2] cf 74 [2] d4 3a [2] e9 }

  condition:
    any of them
}
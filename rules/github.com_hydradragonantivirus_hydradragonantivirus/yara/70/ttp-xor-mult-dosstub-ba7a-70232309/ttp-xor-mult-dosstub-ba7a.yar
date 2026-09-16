rule TTP_XOR_MULT_DOSStub_ba7a {
  strings:
    $key_ba7a = { ee 12 [2] 9a 0a [2] dd 08 [2] 9a 19 [2] d4 15 [2] d8 1f [2] cf 14 [2] d4 5a [2] e9 }

  condition:
    any of them
}
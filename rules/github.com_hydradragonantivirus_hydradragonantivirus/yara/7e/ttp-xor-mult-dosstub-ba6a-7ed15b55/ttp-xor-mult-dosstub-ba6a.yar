rule TTP_XOR_MULT_DOSStub_ba6a {
  strings:
    $key_ba6a = { ee 02 [2] 9a 1a [2] dd 18 [2] 9a 09 [2] d4 05 [2] d8 0f [2] cf 04 [2] d4 4a [2] e9 }

  condition:
    any of them
}
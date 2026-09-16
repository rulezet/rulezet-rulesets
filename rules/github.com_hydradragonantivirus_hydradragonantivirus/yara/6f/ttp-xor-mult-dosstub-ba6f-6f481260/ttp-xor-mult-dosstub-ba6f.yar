rule TTP_XOR_MULT_DOSStub_ba6f {
  strings:
    $key_ba6f = { ee 07 [2] 9a 1f [2] dd 1d [2] 9a 0c [2] d4 00 [2] d8 0a [2] cf 01 [2] d4 4f [2] e9 }

  condition:
    any of them
}
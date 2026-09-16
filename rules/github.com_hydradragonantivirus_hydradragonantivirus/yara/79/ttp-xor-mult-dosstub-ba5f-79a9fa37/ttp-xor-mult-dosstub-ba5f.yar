rule TTP_XOR_MULT_DOSStub_ba5f {
  strings:
    $key_ba5f = { ee 37 [2] 9a 2f [2] dd 2d [2] 9a 3c [2] d4 30 [2] d8 3a [2] cf 31 [2] d4 7f [2] e9 }

  condition:
    any of them
}
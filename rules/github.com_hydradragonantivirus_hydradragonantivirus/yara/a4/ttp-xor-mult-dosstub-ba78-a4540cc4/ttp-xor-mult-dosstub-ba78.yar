rule TTP_XOR_MULT_DOSStub_ba78 {
  strings:
    $key_ba78 = { ee 10 [2] 9a 08 [2] dd 0a [2] 9a 1b [2] d4 17 [2] d8 1d [2] cf 16 [2] d4 58 [2] e9 }

  condition:
    any of them
}
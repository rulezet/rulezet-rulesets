rule TTP_XOR_MULT_DOSStub_ba2d {
  strings:
    $key_ba2d = { ee 45 [2] 9a 5d [2] dd 5f [2] 9a 4e [2] d4 42 [2] d8 48 [2] cf 43 [2] d4 0d [2] e9 }

  condition:
    any of them
}
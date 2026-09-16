rule TTP_XOR_MULT_DOSStub_ba4e {
  strings:
    $key_ba4e = { ee 26 [2] 9a 3e [2] dd 3c [2] 9a 2d [2] d4 21 [2] d8 2b [2] cf 20 [2] d4 6e [2] e9 }

  condition:
    any of them
}
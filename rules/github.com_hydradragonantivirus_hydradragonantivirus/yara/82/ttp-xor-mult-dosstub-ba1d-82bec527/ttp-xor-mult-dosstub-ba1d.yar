rule TTP_XOR_MULT_DOSStub_ba1d {
  strings:
    $key_ba1d = { ee 75 [2] 9a 6d [2] dd 6f [2] 9a 7e [2] d4 72 [2] d8 78 [2] cf 73 [2] d4 3d [2] e9 }

  condition:
    any of them
}
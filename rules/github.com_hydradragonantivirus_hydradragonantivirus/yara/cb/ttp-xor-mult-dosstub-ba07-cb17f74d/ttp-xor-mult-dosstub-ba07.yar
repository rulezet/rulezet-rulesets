rule TTP_XOR_MULT_DOSStub_ba07 {
  strings:
    $key_ba07 = { ee 6f [2] 9a 77 [2] dd 75 [2] 9a 64 [2] d4 68 [2] d8 62 [2] cf 69 [2] d4 27 [2] e9 }

  condition:
    any of them
}
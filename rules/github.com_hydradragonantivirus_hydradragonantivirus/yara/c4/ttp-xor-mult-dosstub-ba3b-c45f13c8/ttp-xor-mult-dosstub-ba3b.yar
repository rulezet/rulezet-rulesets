rule TTP_XOR_MULT_DOSStub_ba3b {
  strings:
    $key_ba3b = { ee 53 [2] 9a 4b [2] dd 49 [2] 9a 58 [2] d4 54 [2] d8 5e [2] cf 55 [2] d4 1b [2] e9 }

  condition:
    any of them
}
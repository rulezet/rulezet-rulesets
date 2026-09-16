rule TTP_XOR_MULT_DOSStub_ba0b {
  strings:
    $key_ba0b = { ee 63 [2] 9a 7b [2] dd 79 [2] 9a 68 [2] d4 64 [2] d8 6e [2] cf 65 [2] d4 2b [2] e9 }

  condition:
    any of them
}
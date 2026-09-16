rule TTP_XOR_MULT_DOSStub_ba6b {
  strings:
    $key_ba6b = { ee 03 [2] 9a 1b [2] dd 19 [2] 9a 08 [2] d4 04 [2] d8 0e [2] cf 05 [2] d4 4b [2] e9 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_ba7c {
  strings:
    $key_ba7c = { ee 14 [2] 9a 0c [2] dd 0e [2] 9a 1f [2] d4 13 [2] d8 19 [2] cf 12 [2] d4 5c [2] e9 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_ba6e {
  strings:
    $key_ba6e = { ee 06 [2] 9a 1e [2] dd 1c [2] 9a 0d [2] d4 01 [2] d8 0b [2] cf 00 [2] d4 4e [2] e9 }

  condition:
    any of them
}
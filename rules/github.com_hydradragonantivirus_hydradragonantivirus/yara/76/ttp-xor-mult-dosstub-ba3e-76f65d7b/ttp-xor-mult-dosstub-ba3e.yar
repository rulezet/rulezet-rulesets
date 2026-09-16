rule TTP_XOR_MULT_DOSStub_ba3e {
  strings:
    $key_ba3e = { ee 56 [2] 9a 4e [2] dd 4c [2] 9a 5d [2] d4 51 [2] d8 5b [2] cf 50 [2] d4 1e [2] e9 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_bafe {
  strings:
    $key_bafe = { ee 96 [2] 9a 8e [2] dd 8c [2] 9a 9d [2] d4 91 [2] d8 9b [2] cf 90 [2] d4 de [2] e9 }

  condition:
    any of them
}
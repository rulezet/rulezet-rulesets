rule TTP_XOR_MULT_DOSStub_baee {
  strings:
    $key_baee = { ee 86 [2] 9a 9e [2] dd 9c [2] 9a 8d [2] d4 81 [2] d8 8b [2] cf 80 [2] d4 ce [2] e9 }

  condition:
    any of them
}
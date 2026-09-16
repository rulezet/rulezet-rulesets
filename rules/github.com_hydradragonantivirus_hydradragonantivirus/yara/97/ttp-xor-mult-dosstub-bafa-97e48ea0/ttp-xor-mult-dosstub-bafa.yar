rule TTP_XOR_MULT_DOSStub_bafa {
  strings:
    $key_bafa = { ee 92 [2] 9a 8a [2] dd 88 [2] 9a 99 [2] d4 95 [2] d8 9f [2] cf 94 [2] d4 da [2] e9 }

  condition:
    any of them
}
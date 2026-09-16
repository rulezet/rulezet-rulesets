rule TTP_XOR_MULT_DOSStub_ba5c {
  strings:
    $key_ba5c = { ee 34 [2] 9a 2c [2] dd 2e [2] 9a 3f [2] d4 33 [2] d8 39 [2] cf 32 [2] d4 7c [2] e9 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_ba2c {
  strings:
    $key_ba2c = { ee 44 [2] 9a 5c [2] dd 5e [2] 9a 4f [2] d4 43 [2] d8 49 [2] cf 42 [2] d4 0c [2] e9 }

  condition:
    any of them
}
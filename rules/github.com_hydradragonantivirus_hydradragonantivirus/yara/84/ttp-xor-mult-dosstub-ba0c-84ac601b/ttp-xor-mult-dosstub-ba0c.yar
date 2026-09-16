rule TTP_XOR_MULT_DOSStub_ba0c {
  strings:
    $key_ba0c = { ee 64 [2] 9a 7c [2] dd 7e [2] 9a 6f [2] d4 63 [2] d8 69 [2] cf 62 [2] d4 2c [2] e9 }

  condition:
    any of them
}
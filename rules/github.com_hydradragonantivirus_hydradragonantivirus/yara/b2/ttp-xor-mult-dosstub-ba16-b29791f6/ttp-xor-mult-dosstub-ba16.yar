rule TTP_XOR_MULT_DOSStub_ba16 {
  strings:
    $key_ba16 = { ee 7e [2] 9a 66 [2] dd 64 [2] 9a 75 [2] d4 79 [2] d8 73 [2] cf 78 [2] d4 36 [2] e9 }

  condition:
    any of them
}
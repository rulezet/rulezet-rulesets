rule TTP_XOR_MULT_DOSStub_ba36 {
  strings:
    $key_ba36 = { ee 5e [2] 9a 46 [2] dd 44 [2] 9a 55 [2] d4 59 [2] d8 53 [2] cf 58 [2] d4 16 [2] e9 }

  condition:
    any of them
}
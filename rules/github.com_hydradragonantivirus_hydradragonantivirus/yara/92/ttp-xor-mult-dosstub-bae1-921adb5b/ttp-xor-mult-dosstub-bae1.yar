rule TTP_XOR_MULT_DOSStub_bae1 {
  strings:
    $key_bae1 = { ee 89 [2] 9a 91 [2] dd 93 [2] 9a 82 [2] d4 8e [2] d8 84 [2] cf 8f [2] d4 c1 [2] e9 }

  condition:
    any of them
}
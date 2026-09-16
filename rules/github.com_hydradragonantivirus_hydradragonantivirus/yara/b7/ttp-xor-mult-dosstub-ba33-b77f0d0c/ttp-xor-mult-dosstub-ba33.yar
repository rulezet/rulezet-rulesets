rule TTP_XOR_MULT_DOSStub_ba33 {
  strings:
    $key_ba33 = { ee 5b [2] 9a 43 [2] dd 41 [2] 9a 50 [2] d4 5c [2] d8 56 [2] cf 5d [2] d4 13 [2] e9 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_ba53 {
  strings:
    $key_ba53 = { ee 3b [2] 9a 23 [2] dd 21 [2] 9a 30 [2] d4 3c [2] d8 36 [2] cf 3d [2] d4 73 [2] e9 }

  condition:
    any of them
}
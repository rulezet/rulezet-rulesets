rule TTP_XOR_MULT_DOSStub_ba03 {
  strings:
    $key_ba03 = { ee 6b [2] 9a 73 [2] dd 71 [2] 9a 60 [2] d4 6c [2] d8 66 [2] cf 6d [2] d4 23 [2] e9 }

  condition:
    any of them
}
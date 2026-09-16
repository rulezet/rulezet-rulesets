rule TTP_XOR_MULT_DOSStub_0410 {
  strings:
    $key_0410 = { 50 78 [2] 24 60 [2] 63 62 [2] 24 73 [2] 6a 7f [2] 66 75 [2] 71 7e [2] 6a 30 [2] 57 }

  condition:
    any of them
}
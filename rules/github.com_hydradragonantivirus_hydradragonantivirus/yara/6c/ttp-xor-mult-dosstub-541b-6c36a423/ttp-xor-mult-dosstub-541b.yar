rule TTP_XOR_MULT_DOSStub_541b {
  strings:
    $key_541b = { 00 73 [2] 74 6b [2] 33 69 [2] 74 78 [2] 3a 74 [2] 36 7e [2] 21 75 [2] 3a 3b [2] 07 }

  condition:
    any of them
}
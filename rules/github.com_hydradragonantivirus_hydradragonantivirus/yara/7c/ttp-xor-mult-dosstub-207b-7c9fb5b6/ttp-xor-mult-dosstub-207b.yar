rule TTP_XOR_MULT_DOSStub_207b {
  strings:
    $key_207b = { 74 13 [2] 00 0b [2] 47 09 [2] 00 18 [2] 4e 14 [2] 42 1e [2] 55 15 [2] 4e 5b [2] 73 }

  condition:
    any of them
}
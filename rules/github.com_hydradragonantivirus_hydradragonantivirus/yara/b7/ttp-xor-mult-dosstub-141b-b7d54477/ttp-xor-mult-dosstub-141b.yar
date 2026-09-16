rule TTP_XOR_MULT_DOSStub_141b {
  strings:
    $key_141b = { 40 73 [2] 34 6b [2] 73 69 [2] 34 78 [2] 7a 74 [2] 76 7e [2] 61 75 [2] 7a 3b [2] 47 }

  condition:
    any of them
}
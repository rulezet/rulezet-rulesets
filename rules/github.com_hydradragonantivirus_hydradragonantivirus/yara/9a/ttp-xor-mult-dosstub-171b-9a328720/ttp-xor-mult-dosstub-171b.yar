rule TTP_XOR_MULT_DOSStub_171b {
  strings:
    $key_171b = { 43 73 [2] 37 6b [2] 70 69 [2] 37 78 [2] 79 74 [2] 75 7e [2] 62 75 [2] 79 3b [2] 44 }

  condition:
    any of them
}
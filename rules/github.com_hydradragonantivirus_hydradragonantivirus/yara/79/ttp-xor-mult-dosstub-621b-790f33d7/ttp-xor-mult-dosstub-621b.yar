rule TTP_XOR_MULT_DOSStub_621b {
  strings:
    $key_621b = { 36 73 [2] 42 6b [2] 05 69 [2] 42 78 [2] 0c 74 [2] 00 7e [2] 17 75 [2] 0c 3b [2] 31 }

  condition:
    any of them
}
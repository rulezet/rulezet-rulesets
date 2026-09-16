rule TTP_XOR_MULT_DOSStub_301b {
  strings:
    $key_301b = { 64 73 [2] 10 6b [2] 57 69 [2] 10 78 [2] 5e 74 [2] 52 7e [2] 45 75 [2] 5e 3b [2] 63 }

  condition:
    any of them
}
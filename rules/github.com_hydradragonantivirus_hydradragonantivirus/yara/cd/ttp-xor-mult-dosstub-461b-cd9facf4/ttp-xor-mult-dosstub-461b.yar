rule TTP_XOR_MULT_DOSStub_461b {
  strings:
    $key_461b = { 12 73 [2] 66 6b [2] 21 69 [2] 66 78 [2] 28 74 [2] 24 7e [2] 33 75 [2] 28 3b [2] 15 }

  condition:
    any of them
}
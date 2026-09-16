rule TTP_XOR_MULT_DOSStub_051b {
  strings:
    $key_051b = { 51 73 [2] 25 6b [2] 62 69 [2] 25 78 [2] 6b 74 [2] 67 7e [2] 70 75 [2] 6b 3b [2] 56 }

  condition:
    any of them
}
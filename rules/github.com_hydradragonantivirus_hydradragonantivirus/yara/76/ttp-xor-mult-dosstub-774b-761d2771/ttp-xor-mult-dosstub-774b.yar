rule TTP_XOR_MULT_DOSStub_774b {
  strings:
    $key_774b = { 23 23 [2] 57 3b [2] 10 39 [2] 57 28 [2] 19 24 [2] 15 2e [2] 02 25 [2] 19 6b [2] 24 }

  condition:
    any of them
}
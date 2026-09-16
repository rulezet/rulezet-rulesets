rule TTP_XOR_MULT_DOSStub_767b {
  strings:
    $key_767b = { 22 13 [2] 56 0b [2] 11 09 [2] 56 18 [2] 18 14 [2] 14 1e [2] 03 15 [2] 18 5b [2] 25 }

  condition:
    any of them
}
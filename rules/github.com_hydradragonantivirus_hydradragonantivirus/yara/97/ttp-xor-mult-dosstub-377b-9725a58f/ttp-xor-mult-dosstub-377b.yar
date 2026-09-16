rule TTP_XOR_MULT_DOSStub_377b {
  strings:
    $key_377b = { 63 13 [2] 17 0b [2] 50 09 [2] 17 18 [2] 59 14 [2] 55 1e [2] 42 15 [2] 59 5b [2] 64 }

  condition:
    any of them
}
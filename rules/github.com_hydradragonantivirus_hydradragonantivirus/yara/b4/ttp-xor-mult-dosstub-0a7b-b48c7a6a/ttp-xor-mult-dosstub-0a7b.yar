rule TTP_XOR_MULT_DOSStub_0a7b {
  strings:
    $key_0a7b = { 5e 13 [2] 2a 0b [2] 6d 09 [2] 2a 18 [2] 64 14 [2] 68 1e [2] 7f 15 [2] 64 5b [2] 59 }

  condition:
    any of them
}
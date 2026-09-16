rule TTP_XOR_MULT_DOSStub_4a2b {
  strings:
    $key_4a2b = { 1e 43 [2] 6a 5b [2] 2d 59 [2] 6a 48 [2] 24 44 [2] 28 4e [2] 3f 45 [2] 24 0b [2] 19 }

  condition:
    any of them
}
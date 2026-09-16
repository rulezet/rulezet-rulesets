rule TTP_XOR_MULT_DOSStub_370b {
  strings:
    $key_370b = { 63 63 [2] 17 7b [2] 50 79 [2] 17 68 [2] 59 64 [2] 55 6e [2] 42 65 [2] 59 2b [2] 64 }

  condition:
    any of them
}
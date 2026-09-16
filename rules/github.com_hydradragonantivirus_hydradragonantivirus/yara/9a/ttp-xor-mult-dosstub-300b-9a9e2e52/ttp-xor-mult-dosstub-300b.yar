rule TTP_XOR_MULT_DOSStub_300b {
  strings:
    $key_300b = { 64 63 [2] 10 7b [2] 57 79 [2] 10 68 [2] 5e 64 [2] 52 6e [2] 45 65 [2] 5e 2b [2] 63 }

  condition:
    any of them
}
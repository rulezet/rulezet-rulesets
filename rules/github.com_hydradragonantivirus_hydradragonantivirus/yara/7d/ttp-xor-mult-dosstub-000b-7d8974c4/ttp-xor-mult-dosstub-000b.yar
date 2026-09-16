rule TTP_XOR_MULT_DOSStub_000b {
  strings:
    $key_000b = { 54 63 [2] 20 7b [2] 67 79 [2] 20 68 [2] 6e 64 [2] 62 6e [2] 75 65 [2] 6e 2b [2] 53 }

  condition:
    any of them
}
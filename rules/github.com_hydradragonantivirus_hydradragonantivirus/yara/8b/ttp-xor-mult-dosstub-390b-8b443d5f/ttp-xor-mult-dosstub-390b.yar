rule TTP_XOR_MULT_DOSStub_390b {
  strings:
    $key_390b = { 6d 63 [2] 19 7b [2] 5e 79 [2] 19 68 [2] 57 64 [2] 5b 6e [2] 4c 65 [2] 57 2b [2] 6a }

  condition:
    any of them
}
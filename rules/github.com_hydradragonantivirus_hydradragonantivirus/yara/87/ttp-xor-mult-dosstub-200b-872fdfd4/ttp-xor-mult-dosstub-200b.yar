rule TTP_XOR_MULT_DOSStub_200b {
  strings:
    $key_200b = { 74 63 [2] 00 7b [2] 47 79 [2] 00 68 [2] 4e 64 [2] 42 6e [2] 55 65 [2] 4e 2b [2] 73 }

  condition:
    any of them
}
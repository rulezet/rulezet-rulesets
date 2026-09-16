rule TTP_XOR_MULT_DOSStub_f40b {
  strings:
    $key_f40b = { a0 63 [2] d4 7b [2] 93 79 [2] d4 68 [2] 9a 64 [2] 96 6e [2] 81 65 [2] 9a 2b [2] a7 }

  condition:
    any of them
}
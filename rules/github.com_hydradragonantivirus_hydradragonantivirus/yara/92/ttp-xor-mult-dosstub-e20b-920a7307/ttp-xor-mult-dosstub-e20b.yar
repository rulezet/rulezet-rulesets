rule TTP_XOR_MULT_DOSStub_e20b {
  strings:
    $key_e20b = { b6 63 [2] c2 7b [2] 85 79 [2] c2 68 [2] 8c 64 [2] 80 6e [2] 97 65 [2] 8c 2b [2] b1 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_5a0b {
  strings:
    $key_5a0b = { 0e 63 [2] 7a 7b [2] 3d 79 [2] 7a 68 [2] 34 64 [2] 38 6e [2] 2f 65 [2] 34 2b [2] 09 }

  condition:
    any of them
}
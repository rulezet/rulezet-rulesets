rule TTP_XOR_MULT_DOSStub_1d0b {
  strings:
    $key_1d0b = { 49 63 [2] 3d 7b [2] 7a 79 [2] 3d 68 [2] 73 64 [2] 7f 6e [2] 68 65 [2] 73 2b [2] 4e }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_1d7b {
  strings:
    $key_1d7b = { 49 13 [2] 3d 0b [2] 7a 09 [2] 3d 18 [2] 73 14 [2] 7f 1e [2] 68 15 [2] 73 5b [2] 4e }

  condition:
    any of them
}
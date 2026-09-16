rule TTP_XOR_MULT_DOSStub_1d1b {
  strings:
    $key_1d1b = { 49 73 [2] 3d 6b [2] 7a 69 [2] 3d 78 [2] 73 74 [2] 7f 7e [2] 68 75 [2] 73 3b [2] 4e }

  condition:
    any of them
}
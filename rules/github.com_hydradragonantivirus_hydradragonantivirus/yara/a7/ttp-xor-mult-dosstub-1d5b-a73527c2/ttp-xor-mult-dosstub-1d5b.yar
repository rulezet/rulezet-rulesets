rule TTP_XOR_MULT_DOSStub_1d5b {
  strings:
    $key_1d5b = { 49 33 [2] 3d 2b [2] 7a 29 [2] 3d 38 [2] 73 34 [2] 7f 3e [2] 68 35 [2] 73 7b [2] 4e }

  condition:
    any of them
}
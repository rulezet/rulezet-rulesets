rule TTP_XOR_MULT_DOSStub_1d6e {
  strings:
    $key_1d6e = { 49 06 [2] 3d 1e [2] 7a 1c [2] 3d 0d [2] 73 01 [2] 7f 0b [2] 68 00 [2] 73 4e [2] 4e }

  condition:
    any of them
}
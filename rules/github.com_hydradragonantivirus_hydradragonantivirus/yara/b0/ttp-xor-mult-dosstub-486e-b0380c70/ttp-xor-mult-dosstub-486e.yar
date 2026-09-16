rule TTP_XOR_MULT_DOSStub_486e {
  strings:
    $key_486e = { 1c 06 [2] 68 1e [2] 2f 1c [2] 68 0d [2] 26 01 [2] 2a 0b [2] 3d 00 [2] 26 4e [2] 1b }

  condition:
    any of them
}
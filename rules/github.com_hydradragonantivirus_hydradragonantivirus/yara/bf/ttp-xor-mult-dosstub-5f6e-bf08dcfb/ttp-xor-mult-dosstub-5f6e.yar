rule TTP_XOR_MULT_DOSStub_5f6e {
  strings:
    $key_5f6e = { 0b 06 [2] 7f 1e [2] 38 1c [2] 7f 0d [2] 31 01 [2] 3d 0b [2] 2a 00 [2] 31 4e [2] 0c }

  condition:
    any of them
}
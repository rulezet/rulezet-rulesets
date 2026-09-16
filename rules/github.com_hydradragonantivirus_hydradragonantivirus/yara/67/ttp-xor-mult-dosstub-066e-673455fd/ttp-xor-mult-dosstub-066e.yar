rule TTP_XOR_MULT_DOSStub_066e {
  strings:
    $key_066e = { 52 06 [2] 26 1e [2] 61 1c [2] 26 0d [2] 68 01 [2] 64 0b [2] 73 00 [2] 68 4e [2] 55 }

  condition:
    any of them
}
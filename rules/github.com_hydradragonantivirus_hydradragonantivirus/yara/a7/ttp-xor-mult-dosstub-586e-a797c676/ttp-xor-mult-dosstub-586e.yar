rule TTP_XOR_MULT_DOSStub_586e {
  strings:
    $key_586e = { 0c 06 [2] 78 1e [2] 3f 1c [2] 78 0d [2] 36 01 [2] 3a 0b [2] 2d 00 [2] 36 4e [2] 0b }

  condition:
    any of them
}
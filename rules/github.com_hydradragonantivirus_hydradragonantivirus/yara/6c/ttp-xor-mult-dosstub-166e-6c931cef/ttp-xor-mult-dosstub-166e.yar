rule TTP_XOR_MULT_DOSStub_166e {
  strings:
    $key_166e = { 42 06 [2] 36 1e [2] 71 1c [2] 36 0d [2] 78 01 [2] 74 0b [2] 63 00 [2] 78 4e [2] 45 }

  condition:
    any of them
}
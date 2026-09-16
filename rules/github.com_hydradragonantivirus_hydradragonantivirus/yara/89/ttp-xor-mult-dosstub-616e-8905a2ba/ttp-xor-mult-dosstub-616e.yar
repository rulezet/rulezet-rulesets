rule TTP_XOR_MULT_DOSStub_616e {
  strings:
    $key_616e = { 35 06 [2] 41 1e [2] 06 1c [2] 41 0d [2] 0f 01 [2] 03 0b [2] 14 00 [2] 0f 4e [2] 32 }

  condition:
    any of them
}
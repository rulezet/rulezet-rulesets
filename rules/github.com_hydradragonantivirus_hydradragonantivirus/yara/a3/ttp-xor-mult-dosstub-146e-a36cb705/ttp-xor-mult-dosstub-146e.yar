rule TTP_XOR_MULT_DOSStub_146e {
  strings:
    $key_146e = { 40 06 [2] 34 1e [2] 73 1c [2] 34 0d [2] 7a 01 [2] 76 0b [2] 61 00 [2] 7a 4e [2] 47 }

  condition:
    any of them
}
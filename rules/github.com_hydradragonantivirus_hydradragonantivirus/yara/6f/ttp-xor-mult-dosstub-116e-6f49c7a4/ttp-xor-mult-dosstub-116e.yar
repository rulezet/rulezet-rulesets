rule TTP_XOR_MULT_DOSStub_116e {
  strings:
    $key_116e = { 45 06 [2] 31 1e [2] 76 1c [2] 31 0d [2] 7f 01 [2] 73 0b [2] 64 00 [2] 7f 4e [2] 42 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_a76e {
  strings:
    $key_a76e = { f3 06 [2] 87 1e [2] c0 1c [2] 87 0d [2] c9 01 [2] c5 0b [2] d2 00 [2] c9 4e [2] f4 }

  condition:
    any of them
}
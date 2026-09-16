rule TTP_XOR_MULT_DOSStub_916e {
  strings:
    $key_916e = { c5 06 [2] b1 1e [2] f6 1c [2] b1 0d [2] ff 01 [2] f3 0b [2] e4 00 [2] ff 4e [2] c2 }

  condition:
    any of them
}
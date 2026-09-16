rule TTP_XOR_MULT_DOSStub_916d {
  strings:
    $key_916d = { c5 05 [2] b1 1d [2] f6 1f [2] b1 0e [2] ff 02 [2] f3 08 [2] e4 03 [2] ff 4d [2] c2 }

  condition:
    any of them
}
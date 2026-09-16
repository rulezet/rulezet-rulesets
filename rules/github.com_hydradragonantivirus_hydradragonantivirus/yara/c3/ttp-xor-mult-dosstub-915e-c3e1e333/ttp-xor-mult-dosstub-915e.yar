rule TTP_XOR_MULT_DOSStub_915e {
  strings:
    $key_915e = { c5 36 [2] b1 2e [2] f6 2c [2] b1 3d [2] ff 31 [2] f3 3b [2] e4 30 [2] ff 7e [2] c2 }

  condition:
    any of them
}
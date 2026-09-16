rule TTP_XOR_MULT_DOSStub_911d {
  strings:
    $key_911d = { c5 75 [2] b1 6d [2] f6 6f [2] b1 7e [2] ff 72 [2] f3 78 [2] e4 73 [2] ff 3d [2] c2 }

  condition:
    any of them
}
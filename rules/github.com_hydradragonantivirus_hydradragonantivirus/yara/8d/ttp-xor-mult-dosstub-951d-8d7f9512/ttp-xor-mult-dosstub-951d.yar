rule TTP_XOR_MULT_DOSStub_951d {
  strings:
    $key_951d = { c1 75 [2] b5 6d [2] f2 6f [2] b5 7e [2] fb 72 [2] f7 78 [2] e0 73 [2] fb 3d [2] c6 }

  condition:
    any of them
}
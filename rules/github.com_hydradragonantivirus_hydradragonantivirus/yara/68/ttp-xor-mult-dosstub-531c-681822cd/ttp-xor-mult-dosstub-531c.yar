rule TTP_XOR_MULT_DOSStub_531c {
  strings:
    $key_531c = { 07 74 [2] 73 6c [2] 34 6e [2] 73 7f [2] 3d 73 [2] 31 79 [2] 26 72 [2] 3d 3c [2] 00 }

  condition:
    any of them
}
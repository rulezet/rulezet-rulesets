rule TTP_XOR_MULT_DOSStub_53f2 {
  strings:
    $key_53f2 = { 07 9a [2] 73 82 [2] 34 80 [2] 73 91 [2] 3d 9d [2] 31 97 [2] 26 9c [2] 3d d2 [2] 00 }

  condition:
    any of them
}
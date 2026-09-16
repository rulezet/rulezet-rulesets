rule TTP_XOR_MULT_DOSStub_53f9 {
  strings:
    $key_53f9 = { 07 91 [2] 73 89 [2] 34 8b [2] 73 9a [2] 3d 96 [2] 31 9c [2] 26 97 [2] 3d d9 [2] 00 }

  condition:
    any of them
}
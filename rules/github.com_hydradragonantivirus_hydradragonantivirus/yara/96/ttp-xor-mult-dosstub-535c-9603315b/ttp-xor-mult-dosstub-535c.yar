rule TTP_XOR_MULT_DOSStub_535c {
  strings:
    $key_535c = { 07 34 [2] 73 2c [2] 34 2e [2] 73 3f [2] 3d 33 [2] 31 39 [2] 26 32 [2] 3d 7c [2] 00 }

  condition:
    any of them
}
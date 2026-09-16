rule TTP_XOR_MULT_DOSStub_384e {
  strings:
    $key_384e = { 6c 26 [2] 18 3e [2] 5f 3c [2] 18 2d [2] 56 21 [2] 5a 2b [2] 4d 20 [2] 56 6e [2] 6b }

  condition:
    any of them
}
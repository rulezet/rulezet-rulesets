rule TTP_XOR_MULT_DOSStub_254d {
  strings:
    $key_254d = { 71 25 [2] 05 3d [2] 42 3f [2] 05 2e [2] 4b 22 [2] 47 28 [2] 50 23 [2] 4b 6d [2] 76 }

  condition:
    any of them
}
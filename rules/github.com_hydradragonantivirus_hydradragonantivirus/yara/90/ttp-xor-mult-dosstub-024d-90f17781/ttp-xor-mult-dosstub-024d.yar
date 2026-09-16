rule TTP_XOR_MULT_DOSStub_024d {
  strings:
    $key_024d = { 56 25 [2] 22 3d [2] 65 3f [2] 22 2e [2] 6c 22 [2] 60 28 [2] 77 23 [2] 6c 6d [2] 51 }

  condition:
    any of them
}
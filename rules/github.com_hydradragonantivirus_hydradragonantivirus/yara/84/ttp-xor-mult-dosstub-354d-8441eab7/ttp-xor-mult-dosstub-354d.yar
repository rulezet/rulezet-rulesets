rule TTP_XOR_MULT_DOSStub_354d {
  strings:
    $key_354d = { 61 25 [2] 15 3d [2] 52 3f [2] 15 2e [2] 5b 22 [2] 57 28 [2] 40 23 [2] 5b 6d [2] 66 }

  condition:
    any of them
}
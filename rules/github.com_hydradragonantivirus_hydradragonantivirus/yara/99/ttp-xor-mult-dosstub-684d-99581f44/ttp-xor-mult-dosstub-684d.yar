rule TTP_XOR_MULT_DOSStub_684d {
  strings:
    $key_684d = { 3c 25 [2] 48 3d [2] 0f 3f [2] 48 2e [2] 06 22 [2] 0a 28 [2] 1d 23 [2] 06 6d [2] 3b }

  condition:
    any of them
}
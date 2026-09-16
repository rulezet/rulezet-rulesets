rule TTP_XOR_MULT_DOSStub_484e {
  strings:
    $key_484e = { 1c 26 [2] 68 3e [2] 2f 3c [2] 68 2d [2] 26 21 [2] 2a 2b [2] 3d 20 [2] 26 6e [2] 1b }

  condition:
    any of them
}
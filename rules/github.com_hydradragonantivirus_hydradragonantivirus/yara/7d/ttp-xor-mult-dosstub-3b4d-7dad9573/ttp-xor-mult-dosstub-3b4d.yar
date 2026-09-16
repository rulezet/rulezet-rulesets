rule TTP_XOR_MULT_DOSStub_3b4d {
  strings:
    $key_3b4d = { 6f 25 [2] 1b 3d [2] 5c 3f [2] 1b 2e [2] 55 22 [2] 59 28 [2] 4e 23 [2] 55 6d [2] 68 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_4b4d {
  strings:
    $key_4b4d = { 1f 25 [2] 6b 3d [2] 2c 3f [2] 6b 2e [2] 25 22 [2] 29 28 [2] 3e 23 [2] 25 6d [2] 18 }

  condition:
    any of them
}
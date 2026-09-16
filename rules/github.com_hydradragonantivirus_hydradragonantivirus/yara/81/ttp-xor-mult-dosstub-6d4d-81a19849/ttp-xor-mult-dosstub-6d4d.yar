rule TTP_XOR_MULT_DOSStub_6d4d {
  strings:
    $key_6d4d = { 39 25 [2] 4d 3d [2] 0a 3f [2] 4d 2e [2] 03 22 [2] 0f 28 [2] 18 23 [2] 03 6d [2] 3e }

  condition:
    any of them
}
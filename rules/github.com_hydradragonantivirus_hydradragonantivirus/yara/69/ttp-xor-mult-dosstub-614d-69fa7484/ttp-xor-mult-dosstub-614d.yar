rule TTP_XOR_MULT_DOSStub_614d {
  strings:
    $key_614d = { 35 25 [2] 41 3d [2] 06 3f [2] 41 2e [2] 0f 22 [2] 03 28 [2] 14 23 [2] 0f 6d [2] 32 }

  condition:
    any of them
}
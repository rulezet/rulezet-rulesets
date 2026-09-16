rule TTP_XOR_MULT_DOSStub_504d {
  strings:
    $key_504d = { 04 25 [2] 70 3d [2] 37 3f [2] 70 2e [2] 3e 22 [2] 32 28 [2] 25 23 [2] 3e 6d [2] 03 }

  condition:
    any of them
}
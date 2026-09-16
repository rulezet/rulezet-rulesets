rule TTP_XOR_MULT_DOSStub_4c52 {
  strings:
    $key_4c52 = { 18 3a [2] 6c 22 [2] 2b 20 [2] 6c 31 [2] 22 3d [2] 2e 37 [2] 39 3c [2] 22 72 [2] 1f }

  condition:
    any of them
}
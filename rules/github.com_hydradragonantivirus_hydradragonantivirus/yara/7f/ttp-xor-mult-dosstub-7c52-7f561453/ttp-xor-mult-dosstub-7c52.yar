rule TTP_XOR_MULT_DOSStub_7c52 {
  strings:
    $key_7c52 = { 28 3a [2] 5c 22 [2] 1b 20 [2] 5c 31 [2] 12 3d [2] 1e 37 [2] 09 3c [2] 12 72 [2] 2f }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_1e52 {
  strings:
    $key_1e52 = { 4a 3a [2] 3e 22 [2] 79 20 [2] 3e 31 [2] 70 3d [2] 7c 37 [2] 6b 3c [2] 70 72 [2] 4d }

  condition:
    any of them
}
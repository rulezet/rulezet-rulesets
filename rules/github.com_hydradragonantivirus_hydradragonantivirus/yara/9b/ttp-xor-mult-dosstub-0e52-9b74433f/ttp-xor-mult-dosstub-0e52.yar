rule TTP_XOR_MULT_DOSStub_0e52 {
  strings:
    $key_0e52 = { 5a 3a [2] 2e 22 [2] 69 20 [2] 2e 31 [2] 60 3d [2] 6c 37 [2] 7b 3c [2] 60 72 [2] 5d }

  condition:
    any of them
}
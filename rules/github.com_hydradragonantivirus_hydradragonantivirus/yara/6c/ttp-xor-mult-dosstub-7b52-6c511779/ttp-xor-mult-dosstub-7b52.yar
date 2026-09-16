rule TTP_XOR_MULT_DOSStub_7b52 {
  strings:
    $key_7b52 = { 2f 3a [2] 5b 22 [2] 1c 20 [2] 5b 31 [2] 15 3d [2] 19 37 [2] 0e 3c [2] 15 72 [2] 28 }

  condition:
    any of them
}
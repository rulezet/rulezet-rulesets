rule TTP_XOR_MULT_DOSStub_1b58 {
  strings:
    $key_1b58 = { 4f 30 [2] 3b 28 [2] 7c 2a [2] 3b 3b [2] 75 37 [2] 79 3d [2] 6e 36 [2] 75 78 [2] 48 }

  condition:
    any of them
}
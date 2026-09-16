rule TTP_XOR_MULT_DOSStub_7b58 {
  strings:
    $key_7b58 = { 2f 30 [2] 5b 28 [2] 1c 2a [2] 5b 3b [2] 15 37 [2] 19 3d [2] 0e 36 [2] 15 78 [2] 28 }

  condition:
    any of them
}
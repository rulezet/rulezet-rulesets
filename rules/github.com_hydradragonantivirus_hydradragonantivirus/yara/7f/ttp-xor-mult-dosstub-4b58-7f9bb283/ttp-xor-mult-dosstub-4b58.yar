rule TTP_XOR_MULT_DOSStub_4b58 {
  strings:
    $key_4b58 = { 1f 30 [2] 6b 28 [2] 2c 2a [2] 6b 3b [2] 25 37 [2] 29 3d [2] 3e 36 [2] 25 78 [2] 18 }

  condition:
    any of them
}
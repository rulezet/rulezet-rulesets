rule TTP_XOR_MULT_DOSStub_ac58 {
  strings:
    $key_ac58 = { f8 30 [2] 8c 28 [2] cb 2a [2] 8c 3b [2] c2 37 [2] ce 3d [2] d9 36 [2] c2 78 [2] ff }

  condition:
    any of them
}
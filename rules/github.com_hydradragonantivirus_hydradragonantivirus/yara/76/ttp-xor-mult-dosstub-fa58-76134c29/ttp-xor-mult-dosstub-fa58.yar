rule TTP_XOR_MULT_DOSStub_fa58 {
  strings:
    $key_fa58 = { ae 30 [2] da 28 [2] 9d 2a [2] da 3b [2] 94 37 [2] 98 3d [2] 8f 36 [2] 94 78 [2] a9 }

  condition:
    any of them
}
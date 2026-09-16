rule TTP_XOR_MULT_DOSStub_bb58 {
  strings:
    $key_bb58 = { ef 30 [2] 9b 28 [2] dc 2a [2] 9b 3b [2] d5 37 [2] d9 3d [2] ce 36 [2] d5 78 [2] e8 }

  condition:
    any of them
}
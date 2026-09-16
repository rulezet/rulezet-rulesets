rule TTP_XOR_MULT_DOSStub_bb55 {
  strings:
    $key_bb55 = { ef 3d [2] 9b 25 [2] dc 27 [2] 9b 36 [2] d5 3a [2] d9 30 [2] ce 3b [2] d5 75 [2] e8 }

  condition:
    any of them
}
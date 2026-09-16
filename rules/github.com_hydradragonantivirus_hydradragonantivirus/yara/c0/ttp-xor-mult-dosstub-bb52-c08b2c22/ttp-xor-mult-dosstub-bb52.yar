rule TTP_XOR_MULT_DOSStub_bb52 {
  strings:
    $key_bb52 = { ef 3a [2] 9b 22 [2] dc 20 [2] 9b 31 [2] d5 3d [2] d9 37 [2] ce 3c [2] d5 72 [2] e8 }

  condition:
    any of them
}
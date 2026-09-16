rule TTP_XOR_MULT_DOSStub_bb4f {
  strings:
    $key_bb4f = { ef 27 [2] 9b 3f [2] dc 3d [2] 9b 2c [2] d5 20 [2] d9 2a [2] ce 21 [2] d5 6f [2] e8 }

  condition:
    any of them
}
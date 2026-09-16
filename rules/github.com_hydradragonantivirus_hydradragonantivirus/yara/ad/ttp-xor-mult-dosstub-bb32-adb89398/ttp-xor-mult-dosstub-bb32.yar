rule TTP_XOR_MULT_DOSStub_bb32 {
  strings:
    $key_bb32 = { ef 5a [2] 9b 42 [2] dc 40 [2] 9b 51 [2] d5 5d [2] d9 57 [2] ce 5c [2] d5 12 [2] e8 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_bb16 {
  strings:
    $key_bb16 = { ef 7e [2] 9b 66 [2] dc 64 [2] 9b 75 [2] d5 79 [2] d9 73 [2] ce 78 [2] d5 36 [2] e8 }

  condition:
    any of them
}
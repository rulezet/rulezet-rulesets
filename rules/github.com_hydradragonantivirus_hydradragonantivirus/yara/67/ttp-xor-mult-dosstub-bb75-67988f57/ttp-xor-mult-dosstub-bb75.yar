rule TTP_XOR_MULT_DOSStub_bb75 {
  strings:
    $key_bb75 = { ef 1d [2] 9b 05 [2] dc 07 [2] 9b 16 [2] d5 1a [2] d9 10 [2] ce 1b [2] d5 55 [2] e8 }

  condition:
    any of them
}
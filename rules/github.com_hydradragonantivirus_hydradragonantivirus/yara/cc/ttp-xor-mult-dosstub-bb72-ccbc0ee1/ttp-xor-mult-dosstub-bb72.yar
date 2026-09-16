rule TTP_XOR_MULT_DOSStub_bb72 {
  strings:
    $key_bb72 = { ef 1a [2] 9b 02 [2] dc 00 [2] 9b 11 [2] d5 1d [2] d9 17 [2] ce 1c [2] d5 52 [2] e8 }

  condition:
    any of them
}
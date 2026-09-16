rule TTP_XOR_MULT_DOSStub_bb59 {
  strings:
    $key_bb59 = { ef 31 [2] 9b 29 [2] dc 2b [2] 9b 3a [2] d5 36 [2] d9 3c [2] ce 37 [2] d5 79 [2] e8 }

  condition:
    any of them
}
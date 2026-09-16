rule TTP_XOR_MULT_DOSStub_bb09 {
  strings:
    $key_bb09 = { ef 61 [2] 9b 79 [2] dc 7b [2] 9b 6a [2] d5 66 [2] d9 6c [2] ce 67 [2] d5 29 [2] e8 }

  condition:
    any of them
}
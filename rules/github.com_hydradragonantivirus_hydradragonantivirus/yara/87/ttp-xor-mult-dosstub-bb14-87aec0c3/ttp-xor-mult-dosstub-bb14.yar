rule TTP_XOR_MULT_DOSStub_bb14 {
  strings:
    $key_bb14 = { ef 7c [2] 9b 64 [2] dc 66 [2] 9b 77 [2] d5 7b [2] d9 71 [2] ce 7a [2] d5 34 [2] e8 }

  condition:
    any of them
}
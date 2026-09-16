rule TTP_XOR_MULT_DOSStub_bb39 {
  strings:
    $key_bb39 = { ef 51 [2] 9b 49 [2] dc 4b [2] 9b 5a [2] d5 56 [2] d9 5c [2] ce 57 [2] d5 19 [2] e8 }

  condition:
    any of them
}
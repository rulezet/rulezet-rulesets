rule TTP_XOR_MULT_DOSStub_4dfa {
  strings:
    $key_4dfa = { 19 92 [2] 6d 8a [2] 2a 88 [2] 6d 99 [2] 23 95 [2] 2f 9f [2] 38 94 [2] 23 da [2] 1e }

  condition:
    any of them
}
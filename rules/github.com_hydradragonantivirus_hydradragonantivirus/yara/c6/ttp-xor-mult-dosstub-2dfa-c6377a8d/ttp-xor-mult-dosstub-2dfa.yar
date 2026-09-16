rule TTP_XOR_MULT_DOSStub_2dfa {
  strings:
    $key_2dfa = { 79 92 [2] 0d 8a [2] 4a 88 [2] 0d 99 [2] 43 95 [2] 4f 9f [2] 58 94 [2] 43 da [2] 7e }

  condition:
    any of them
}
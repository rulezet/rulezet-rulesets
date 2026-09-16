rule TTP_XOR_MULT_DOSStub_0dfa {
  strings:
    $key_0dfa = { 59 92 [2] 2d 8a [2] 6a 88 [2] 2d 99 [2] 63 95 [2] 6f 9f [2] 78 94 [2] 63 da [2] 5e }

  condition:
    any of them
}
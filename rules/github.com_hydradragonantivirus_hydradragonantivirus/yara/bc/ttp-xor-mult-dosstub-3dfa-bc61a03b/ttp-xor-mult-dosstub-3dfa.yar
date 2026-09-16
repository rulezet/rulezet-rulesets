rule TTP_XOR_MULT_DOSStub_3dfa {
  strings:
    $key_3dfa = { 69 92 [2] 1d 8a [2] 5a 88 [2] 1d 99 [2] 53 95 [2] 5f 9f [2] 48 94 [2] 53 da [2] 6e }

  condition:
    any of them
}
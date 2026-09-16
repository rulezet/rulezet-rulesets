rule TTP_XOR_MULT_DOSStub_1ffa {
  strings:
    $key_1ffa = { 4b 92 [2] 3f 8a [2] 78 88 [2] 3f 99 [2] 71 95 [2] 7d 9f [2] 6a 94 [2] 71 da [2] 4c }

  condition:
    any of them
}
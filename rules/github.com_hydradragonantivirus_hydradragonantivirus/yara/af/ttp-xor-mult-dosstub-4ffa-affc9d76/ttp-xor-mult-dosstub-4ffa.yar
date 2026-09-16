rule TTP_XOR_MULT_DOSStub_4ffa {
  strings:
    $key_4ffa = { 1b 92 [2] 6f 8a [2] 28 88 [2] 6f 99 [2] 21 95 [2] 2d 9f [2] 3a 94 [2] 21 da [2] 1c }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_3ffa {
  strings:
    $key_3ffa = { 6b 92 [2] 1f 8a [2] 58 88 [2] 1f 99 [2] 51 95 [2] 5d 9f [2] 4a 94 [2] 51 da [2] 6c }

  condition:
    any of them
}
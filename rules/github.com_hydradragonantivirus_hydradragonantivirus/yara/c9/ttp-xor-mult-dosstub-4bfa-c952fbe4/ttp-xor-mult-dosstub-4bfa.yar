rule TTP_XOR_MULT_DOSStub_4bfa {
  strings:
    $key_4bfa = { 1f 92 [2] 6b 8a [2] 2c 88 [2] 6b 99 [2] 25 95 [2] 29 9f [2] 3e 94 [2] 25 da [2] 18 }

  condition:
    any of them
}
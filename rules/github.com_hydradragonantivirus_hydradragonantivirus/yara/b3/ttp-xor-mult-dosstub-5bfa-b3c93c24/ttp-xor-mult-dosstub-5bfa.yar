rule TTP_XOR_MULT_DOSStub_5bfa {
  strings:
    $key_5bfa = { 0f 92 [2] 7b 8a [2] 3c 88 [2] 7b 99 [2] 35 95 [2] 39 9f [2] 2e 94 [2] 35 da [2] 08 }

  condition:
    any of them
}
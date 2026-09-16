rule TTP_XOR_MULT_DOSStub_a970 {
  strings:
    $key_a970 = { fd 18 [2] 89 00 [2] ce 02 [2] 89 13 [2] c7 1f [2] cb 15 [2] dc 1e [2] c7 50 [2] fa }

  condition:
    any of them
}
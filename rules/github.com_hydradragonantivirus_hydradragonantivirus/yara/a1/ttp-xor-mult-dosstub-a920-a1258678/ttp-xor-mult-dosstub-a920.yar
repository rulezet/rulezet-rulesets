rule TTP_XOR_MULT_DOSStub_a920 {
  strings:
    $key_a920 = { fd 48 [2] 89 50 [2] ce 52 [2] 89 43 [2] c7 4f [2] cb 45 [2] dc 4e [2] c7 00 [2] fa }

  condition:
    any of them
}
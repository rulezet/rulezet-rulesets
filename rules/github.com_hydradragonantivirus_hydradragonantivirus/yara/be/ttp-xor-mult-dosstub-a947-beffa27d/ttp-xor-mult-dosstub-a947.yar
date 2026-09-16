rule TTP_XOR_MULT_DOSStub_a947 {
  strings:
    $key_a947 = { fd 2f [2] 89 37 [2] ce 35 [2] 89 24 [2] c7 28 [2] cb 22 [2] dc 29 [2] c7 67 [2] fa }

  condition:
    any of them
}
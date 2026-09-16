rule TTP_XOR_MULT_DOSStub_a900 {
  strings:
    $key_a900 = { fd 68 [2] 89 70 [2] ce 72 [2] 89 63 [2] c7 6f [2] cb 65 [2] dc 6e [2] c7 20 [2] fa }

  condition:
    any of them
}
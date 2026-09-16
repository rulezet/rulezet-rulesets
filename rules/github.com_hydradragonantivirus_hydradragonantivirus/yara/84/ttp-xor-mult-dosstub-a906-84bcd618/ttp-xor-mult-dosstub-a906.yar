rule TTP_XOR_MULT_DOSStub_a906 {
  strings:
    $key_a906 = { fd 6e [2] 89 76 [2] ce 74 [2] 89 65 [2] c7 69 [2] cb 63 [2] dc 68 [2] c7 26 [2] fa }

  condition:
    any of them
}
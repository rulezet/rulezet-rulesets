rule TTP_XOR_MULT_DOSStub_a951 {
  strings:
    $key_a951 = { fd 39 [2] 89 21 [2] ce 23 [2] 89 32 [2] c7 3e [2] cb 34 [2] dc 3f [2] c7 71 [2] fa }

  condition:
    any of them
}
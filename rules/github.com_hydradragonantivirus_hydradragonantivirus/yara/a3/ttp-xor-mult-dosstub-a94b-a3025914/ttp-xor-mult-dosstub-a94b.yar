rule TTP_XOR_MULT_DOSStub_a94b {
  strings:
    $key_a94b = { fd 23 [2] 89 3b [2] ce 39 [2] 89 28 [2] c7 24 [2] cb 2e [2] dc 25 [2] c7 6b [2] fa }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_a919 {
  strings:
    $key_a919 = { fd 71 [2] 89 69 [2] ce 6b [2] 89 7a [2] c7 76 [2] cb 7c [2] dc 77 [2] c7 39 [2] fa }

  condition:
    any of them
}
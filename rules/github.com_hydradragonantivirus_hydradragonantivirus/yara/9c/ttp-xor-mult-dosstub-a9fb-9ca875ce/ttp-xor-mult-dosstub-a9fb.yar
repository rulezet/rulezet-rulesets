rule TTP_XOR_MULT_DOSStub_a9fb {
  strings:
    $key_a9fb = { fd 93 [2] 89 8b [2] ce 89 [2] 89 98 [2] c7 94 [2] cb 9e [2] dc 95 [2] c7 db [2] fa }

  condition:
    any of them
}
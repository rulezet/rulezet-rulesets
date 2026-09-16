rule TTP_XOR_MULT_DOSStub_a9ec {
  strings:
    $key_a9ec = { fd 84 [2] 89 9c [2] ce 9e [2] 89 8f [2] c7 83 [2] cb 89 [2] dc 82 [2] c7 cc [2] fa }

  condition:
    any of them
}
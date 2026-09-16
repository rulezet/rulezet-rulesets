rule TTP_XOR_MULT_DOSStub_a9eb {
  strings:
    $key_a9eb = { fd 83 [2] 89 9b [2] ce 99 [2] 89 88 [2] c7 84 [2] cb 8e [2] dc 85 [2] c7 cb [2] fa }

  condition:
    any of them
}
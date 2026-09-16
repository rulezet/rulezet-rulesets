rule TTP_XOR_MULT_DOSStub_a9f3 {
  strings:
    $key_a9f3 = { fd 9b [2] 89 83 [2] ce 81 [2] 89 90 [2] c7 9c [2] cb 96 [2] dc 9d [2] c7 d3 [2] fa }

  condition:
    any of them
}
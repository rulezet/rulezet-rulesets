rule TTP_XOR_MULT_DOSStub_a937 {
  strings:
    $key_a937 = { fd 5f [2] 89 47 [2] ce 45 [2] 89 54 [2] c7 58 [2] cb 52 [2] dc 59 [2] c7 17 [2] fa }

  condition:
    any of them
}
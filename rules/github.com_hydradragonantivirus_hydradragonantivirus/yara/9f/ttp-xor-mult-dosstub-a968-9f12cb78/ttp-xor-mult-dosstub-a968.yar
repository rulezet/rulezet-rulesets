rule TTP_XOR_MULT_DOSStub_a968 {
  strings:
    $key_a968 = { fd 00 [2] 89 18 [2] ce 1a [2] 89 0b [2] c7 07 [2] cb 0d [2] dc 06 [2] c7 48 [2] fa }

  condition:
    any of them
}
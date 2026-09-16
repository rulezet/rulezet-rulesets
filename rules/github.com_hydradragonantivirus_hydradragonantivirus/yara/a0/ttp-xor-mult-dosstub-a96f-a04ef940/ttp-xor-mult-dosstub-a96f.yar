rule TTP_XOR_MULT_DOSStub_a96f {
  strings:
    $key_a96f = { fd 07 [2] 89 1f [2] ce 1d [2] 89 0c [2] c7 00 [2] cb 0a [2] dc 01 [2] c7 4f [2] fa }

  condition:
    any of them
}
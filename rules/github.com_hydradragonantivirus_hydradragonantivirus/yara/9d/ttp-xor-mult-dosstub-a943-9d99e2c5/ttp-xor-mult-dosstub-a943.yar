rule TTP_XOR_MULT_DOSStub_a943 {
  strings:
    $key_a943 = { fd 2b [2] 89 33 [2] ce 31 [2] 89 20 [2] c7 2c [2] cb 26 [2] dc 2d [2] c7 63 [2] fa }

  condition:
    any of them
}
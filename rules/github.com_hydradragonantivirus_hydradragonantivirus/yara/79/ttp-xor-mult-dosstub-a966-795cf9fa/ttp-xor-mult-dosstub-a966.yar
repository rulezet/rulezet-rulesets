rule TTP_XOR_MULT_DOSStub_a966 {
  strings:
    $key_a966 = { fd 0e [2] 89 16 [2] ce 14 [2] 89 05 [2] c7 09 [2] cb 03 [2] dc 08 [2] c7 46 [2] fa }

  condition:
    any of them
}
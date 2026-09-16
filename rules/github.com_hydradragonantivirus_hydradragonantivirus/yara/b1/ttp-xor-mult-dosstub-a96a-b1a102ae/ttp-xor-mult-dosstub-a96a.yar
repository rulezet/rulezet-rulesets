rule TTP_XOR_MULT_DOSStub_a96a {
  strings:
    $key_a96a = { fd 02 [2] 89 1a [2] ce 18 [2] 89 09 [2] c7 05 [2] cb 0f [2] dc 04 [2] c7 4a [2] fa }

  condition:
    any of them
}
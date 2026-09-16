rule TTP_XOR_MULT_DOSStub_a92f {
  strings:
    $key_a92f = { fd 47 [2] 89 5f [2] ce 5d [2] 89 4c [2] c7 40 [2] cb 4a [2] dc 41 [2] c7 0f [2] fa }

  condition:
    any of them
}
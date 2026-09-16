rule TTP_XOR_MULT_DOSStub_a90f {
  strings:
    $key_a90f = { fd 67 [2] 89 7f [2] ce 7d [2] 89 6c [2] c7 60 [2] cb 6a [2] dc 61 [2] c7 2f [2] fa }

  condition:
    any of them
}
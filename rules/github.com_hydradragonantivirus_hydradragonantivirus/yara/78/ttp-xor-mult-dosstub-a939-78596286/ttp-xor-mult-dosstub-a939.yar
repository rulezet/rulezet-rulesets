rule TTP_XOR_MULT_DOSStub_a939 {
  strings:
    $key_a939 = { fd 51 [2] 89 49 [2] ce 4b [2] 89 5a [2] c7 56 [2] cb 5c [2] dc 57 [2] c7 19 [2] fa }

  condition:
    any of them
}
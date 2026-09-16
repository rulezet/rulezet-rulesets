rule TTP_XOR_MULT_DOSStub_a934 {
  strings:
    $key_a934 = { fd 5c [2] 89 44 [2] ce 46 [2] 89 57 [2] c7 5b [2] cb 51 [2] dc 5a [2] c7 14 [2] fa }

  condition:
    any of them
}
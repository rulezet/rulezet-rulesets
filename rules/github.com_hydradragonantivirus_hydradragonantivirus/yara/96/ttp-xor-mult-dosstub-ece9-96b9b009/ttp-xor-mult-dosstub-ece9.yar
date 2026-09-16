rule TTP_XOR_MULT_DOSStub_ece9 {
  strings:
    $key_ece9 = { b8 81 [2] cc 99 [2] 8b 9b [2] cc 8a [2] 82 86 [2] 8e 8c [2] 99 87 [2] 82 c9 [2] bf }

  condition:
    any of them
}
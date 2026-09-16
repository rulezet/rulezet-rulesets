rule TTP_XOR_MULT_DOSStub_d869 {
  strings:
    $key_d869 = { 8c 01 [2] f8 19 [2] bf 1b [2] f8 0a [2] b6 06 [2] ba 0c [2] ad 07 [2] b6 49 [2] 8b }

  condition:
    any of them
}
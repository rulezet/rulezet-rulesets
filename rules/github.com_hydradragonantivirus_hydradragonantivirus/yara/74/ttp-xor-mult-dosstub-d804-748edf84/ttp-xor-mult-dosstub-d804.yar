rule TTP_XOR_MULT_DOSStub_d804 {
  strings:
    $key_d804 = { 8c 6c [2] f8 74 [2] bf 76 [2] f8 67 [2] b6 6b [2] ba 61 [2] ad 6a [2] b6 24 [2] 8b }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_d824 {
  strings:
    $key_d824 = { 8c 4c [2] f8 54 [2] bf 56 [2] f8 47 [2] b6 4b [2] ba 41 [2] ad 4a [2] b6 04 [2] 8b }

  condition:
    any of them
}
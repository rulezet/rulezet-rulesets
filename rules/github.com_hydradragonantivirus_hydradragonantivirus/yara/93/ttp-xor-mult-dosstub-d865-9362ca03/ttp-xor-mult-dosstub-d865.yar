rule TTP_XOR_MULT_DOSStub_d865 {
  strings:
    $key_d865 = { 8c 0d [2] f8 15 [2] bf 17 [2] f8 06 [2] b6 0a [2] ba 00 [2] ad 0b [2] b6 45 [2] 8b }

  condition:
    any of them
}
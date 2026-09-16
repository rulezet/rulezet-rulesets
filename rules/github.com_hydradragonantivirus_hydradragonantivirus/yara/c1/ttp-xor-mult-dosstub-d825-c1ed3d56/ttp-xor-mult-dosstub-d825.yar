rule TTP_XOR_MULT_DOSStub_d825 {
  strings:
    $key_d825 = { 8c 4d [2] f8 55 [2] bf 57 [2] f8 46 [2] b6 4a [2] ba 40 [2] ad 4b [2] b6 05 [2] 8b }

  condition:
    any of them
}
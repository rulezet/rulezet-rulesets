rule TTP_XOR_MULT_DOSStub_d873 {
  strings:
    $key_d873 = { 8c 1b [2] f8 03 [2] bf 01 [2] f8 10 [2] b6 1c [2] ba 16 [2] ad 1d [2] b6 53 [2] 8b }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_d874 {
  strings:
    $key_d874 = { 8c 1c [2] f8 04 [2] bf 06 [2] f8 17 [2] b6 1b [2] ba 11 [2] ad 1a [2] b6 54 [2] 8b }

  condition:
    any of them
}
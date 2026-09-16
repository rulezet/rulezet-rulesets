rule TTP_XOR_MULT_DOSStub_d16b {
  strings:
    $key_d16b = { 85 03 [2] f1 1b [2] b6 19 [2] f1 08 [2] bf 04 [2] b3 0e [2] a4 05 [2] bf 4b [2] 82 }

  condition:
    any of them
}
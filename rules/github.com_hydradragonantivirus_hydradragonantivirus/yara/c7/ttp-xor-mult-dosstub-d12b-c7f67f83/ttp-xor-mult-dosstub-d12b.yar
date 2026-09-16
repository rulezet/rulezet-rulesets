rule TTP_XOR_MULT_DOSStub_d12b {
  strings:
    $key_d12b = { 85 43 [2] f1 5b [2] b6 59 [2] f1 48 [2] bf 44 [2] b3 4e [2] a4 45 [2] bf 0b [2] 82 }

  condition:
    any of them
}
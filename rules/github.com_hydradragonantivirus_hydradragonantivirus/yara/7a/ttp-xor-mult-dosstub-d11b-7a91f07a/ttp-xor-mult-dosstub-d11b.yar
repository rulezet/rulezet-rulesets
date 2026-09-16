rule TTP_XOR_MULT_DOSStub_d11b {
  strings:
    $key_d11b = { 85 73 [2] f1 6b [2] b6 69 [2] f1 78 [2] bf 74 [2] b3 7e [2] a4 75 [2] bf 3b [2] 82 }

  condition:
    any of them
}
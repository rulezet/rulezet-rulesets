rule TTP_XOR_MULT_DOSStub_d1e0 {
  strings:
    $key_d1e0 = { 85 88 [2] f1 90 [2] b6 92 [2] f1 83 [2] bf 8f [2] b3 85 [2] a4 8e [2] bf c0 [2] 82 }

  condition:
    any of them
}
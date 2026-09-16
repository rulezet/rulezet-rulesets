rule TTP_XOR_MULT_DOSStub_9181 {
  strings:
    $key_9181 = { c5 e9 [2] b1 f1 [2] f6 f3 [2] b1 e2 [2] ff ee [2] f3 e4 [2] e4 ef [2] ff a1 [2] c2 }

  condition:
    any of them
}
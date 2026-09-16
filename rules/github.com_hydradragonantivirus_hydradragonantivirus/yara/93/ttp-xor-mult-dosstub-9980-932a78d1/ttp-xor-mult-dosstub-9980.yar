rule TTP_XOR_MULT_DOSStub_9980 {
  strings:
    $key_9980 = { cd e8 [2] b9 f0 [2] fe f2 [2] b9 e3 [2] f7 ef [2] fb e5 [2] ec ee [2] f7 a0 [2] ca }

  condition:
    any of them
}
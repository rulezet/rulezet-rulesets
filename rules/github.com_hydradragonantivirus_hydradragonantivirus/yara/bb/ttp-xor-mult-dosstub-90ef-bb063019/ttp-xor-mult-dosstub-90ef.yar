rule TTP_XOR_MULT_DOSStub_90ef {
  strings:
    $key_90ef = { c4 87 [2] b0 9f [2] f7 9d [2] b0 8c [2] fe 80 [2] f2 8a [2] e5 81 [2] fe cf [2] c3 }

  condition:
    any of them
}
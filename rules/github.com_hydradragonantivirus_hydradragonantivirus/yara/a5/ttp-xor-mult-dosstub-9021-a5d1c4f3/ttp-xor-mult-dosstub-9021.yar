rule TTP_XOR_MULT_DOSStub_9021 {
  strings:
    $key_9021 = { c4 49 [2] b0 51 [2] f7 53 [2] b0 42 [2] fe 4e [2] f2 44 [2] e5 4f [2] fe 01 [2] c3 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_90f5 {
  strings:
    $key_90f5 = { c4 9d [2] b0 85 [2] f7 87 [2] b0 96 [2] fe 9a [2] f2 90 [2] e5 9b [2] fe d5 [2] c3 }

  condition:
    any of them
}
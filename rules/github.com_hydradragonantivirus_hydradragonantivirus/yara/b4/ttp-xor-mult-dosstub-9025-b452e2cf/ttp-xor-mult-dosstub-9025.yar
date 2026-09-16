rule TTP_XOR_MULT_DOSStub_9025 {
  strings:
    $key_9025 = { c4 4d [2] b0 55 [2] f7 57 [2] b0 46 [2] fe 4a [2] f2 40 [2] e5 4b [2] fe 05 [2] c3 }

  condition:
    any of them
}
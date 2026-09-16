rule TTP_XOR_MULT_DOSStub_906c {
  strings:
    $key_906c = { c4 04 [2] b0 1c [2] f7 1e [2] b0 0f [2] fe 03 [2] f2 09 [2] e5 02 [2] fe 4c [2] c3 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_90e3 {
  strings:
    $key_90e3 = { c4 8b [2] b0 93 [2] f7 91 [2] b0 80 [2] fe 8c [2] f2 86 [2] e5 8d [2] fe c3 [2] c3 }

  condition:
    any of them
}
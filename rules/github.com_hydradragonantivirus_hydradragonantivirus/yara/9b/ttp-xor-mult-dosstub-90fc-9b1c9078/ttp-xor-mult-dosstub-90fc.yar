rule TTP_XOR_MULT_DOSStub_90fc {
  strings:
    $key_90fc = { c4 94 [2] b0 8c [2] f7 8e [2] b0 9f [2] fe 93 [2] f2 99 [2] e5 92 [2] fe dc [2] c3 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_90eb {
  strings:
    $key_90eb = { c4 83 [2] b0 9b [2] f7 99 [2] b0 88 [2] fe 84 [2] f2 8e [2] e5 85 [2] fe cb [2] c3 }

  condition:
    any of them
}
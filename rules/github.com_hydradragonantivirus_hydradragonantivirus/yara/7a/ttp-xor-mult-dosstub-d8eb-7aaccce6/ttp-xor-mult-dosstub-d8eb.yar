rule TTP_XOR_MULT_DOSStub_d8eb {
  strings:
    $key_d8eb = { 8c 83 [2] f8 9b [2] bf 99 [2] f8 88 [2] b6 84 [2] ba 8e [2] ad 85 [2] b6 cb [2] 8b }

  condition:
    any of them
}
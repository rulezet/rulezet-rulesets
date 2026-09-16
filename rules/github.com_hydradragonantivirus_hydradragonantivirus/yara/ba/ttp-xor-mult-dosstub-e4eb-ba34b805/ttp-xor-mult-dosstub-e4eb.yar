rule TTP_XOR_MULT_DOSStub_e4eb {
  strings:
    $key_e4eb = { b0 83 [2] c4 9b [2] 83 99 [2] c4 88 [2] 8a 84 [2] 86 8e [2] 91 85 [2] 8a cb [2] b7 }

  condition:
    any of them
}
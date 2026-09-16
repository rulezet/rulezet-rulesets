rule TTP_XOR_MULT_DOSStub_e2eb {
  strings:
    $key_e2eb = { b6 83 [2] c2 9b [2] 85 99 [2] c2 88 [2] 8c 84 [2] 80 8e [2] 97 85 [2] 8c cb [2] b1 }

  condition:
    any of them
}
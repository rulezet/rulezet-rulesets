rule TTP_XOR_MULT_DOSStub_c2eb {
  strings:
    $key_c2eb = { 96 83 [2] e2 9b [2] a5 99 [2] e2 88 [2] ac 84 [2] a0 8e [2] b7 85 [2] ac cb [2] 91 }

  condition:
    any of them
}
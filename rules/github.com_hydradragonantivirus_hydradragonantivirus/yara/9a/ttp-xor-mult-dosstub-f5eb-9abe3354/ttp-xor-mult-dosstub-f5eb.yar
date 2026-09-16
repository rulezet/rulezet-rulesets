rule TTP_XOR_MULT_DOSStub_f5eb {
  strings:
    $key_f5eb = { a1 83 [2] d5 9b [2] 92 99 [2] d5 88 [2] 9b 84 [2] 97 8e [2] 80 85 [2] 9b cb [2] a6 }

  condition:
    any of them
}
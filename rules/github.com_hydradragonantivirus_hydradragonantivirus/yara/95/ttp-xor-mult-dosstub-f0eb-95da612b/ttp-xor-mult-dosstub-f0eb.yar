rule TTP_XOR_MULT_DOSStub_f0eb {
  strings:
    $key_f0eb = { a4 83 [2] d0 9b [2] 97 99 [2] d0 88 [2] 9e 84 [2] 92 8e [2] 85 85 [2] 9e cb [2] a3 }

  condition:
    any of them
}
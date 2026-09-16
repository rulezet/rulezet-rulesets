rule TTP_XOR_MULT_DOSStub_f516 {
  strings:
    $key_f516 = { a1 7e [2] d5 66 [2] 92 64 [2] d5 75 [2] 9b 79 [2] 97 73 [2] 80 78 [2] 9b 36 [2] a6 }

  condition:
    any of them
}
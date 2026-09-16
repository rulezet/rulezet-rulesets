rule TTP_XOR_MULT_DOSStub_f51b {
  strings:
    $key_f51b = { a1 73 [2] d5 6b [2] 92 69 [2] d5 78 [2] 9b 74 [2] 97 7e [2] 80 75 [2] 9b 3b [2] a6 }

  condition:
    any of them
}
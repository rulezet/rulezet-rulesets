rule TTP_XOR_MULT_DOSStub_f57d {
  strings:
    $key_f57d = { a1 15 [2] d5 0d [2] 92 0f [2] d5 1e [2] 9b 12 [2] 97 18 [2] 80 13 [2] 9b 5d [2] a6 }

  condition:
    any of them
}
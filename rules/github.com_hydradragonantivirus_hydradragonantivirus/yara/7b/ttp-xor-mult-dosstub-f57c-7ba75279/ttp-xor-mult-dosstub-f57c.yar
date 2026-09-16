rule TTP_XOR_MULT_DOSStub_f57c {
  strings:
    $key_f57c = { a1 14 [2] d5 0c [2] 92 0e [2] d5 1f [2] 9b 13 [2] 97 19 [2] 80 12 [2] 9b 5c [2] a6 }

  condition:
    any of them
}
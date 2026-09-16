rule TTP_XOR_MULT_DOSStub_f52b {
  strings:
    $key_f52b = { a1 43 [2] d5 5b [2] 92 59 [2] d5 48 [2] 9b 44 [2] 97 4e [2] 80 45 [2] 9b 0b [2] a6 }

  condition:
    any of them
}
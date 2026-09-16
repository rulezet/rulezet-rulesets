rule TTP_XOR_MULT_DOSStub_f53c {
  strings:
    $key_f53c = { a1 54 [2] d5 4c [2] 92 4e [2] d5 5f [2] 9b 53 [2] 97 59 [2] 80 52 [2] 9b 1c [2] a6 }

  condition:
    any of them
}
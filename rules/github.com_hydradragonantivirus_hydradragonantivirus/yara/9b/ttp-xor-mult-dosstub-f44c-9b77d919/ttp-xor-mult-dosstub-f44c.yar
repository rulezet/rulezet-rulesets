rule TTP_XOR_MULT_DOSStub_f44c {
  strings:
    $key_f44c = { a0 24 [2] d4 3c [2] 93 3e [2] d4 2f [2] 9a 23 [2] 96 29 [2] 81 22 [2] 9a 6c [2] a7 }

  condition:
    any of them
}
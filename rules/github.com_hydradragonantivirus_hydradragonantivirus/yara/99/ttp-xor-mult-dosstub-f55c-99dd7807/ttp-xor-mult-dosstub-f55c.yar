rule TTP_XOR_MULT_DOSStub_f55c {
  strings:
    $key_f55c = { a1 34 [2] d5 2c [2] 92 2e [2] d5 3f [2] 9b 33 [2] 97 39 [2] 80 32 [2] 9b 7c [2] a6 }

  condition:
    any of them
}
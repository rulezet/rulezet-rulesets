rule TTP_XOR_MULT_DOSStub_f05c {
  strings:
    $key_f05c = { a4 34 [2] d0 2c [2] 97 2e [2] d0 3f [2] 9e 33 [2] 92 39 [2] 85 32 [2] 9e 7c [2] a3 }

  condition:
    any of them
}
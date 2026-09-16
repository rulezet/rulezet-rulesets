rule TTP_XOR_MULT_DOSStub_f05b {
  strings:
    $key_f05b = { a4 33 [2] d0 2b [2] 97 29 [2] d0 38 [2] 9e 34 [2] 92 3e [2] 85 35 [2] 9e 7b [2] a3 }

  condition:
    any of them
}
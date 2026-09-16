rule TTP_XOR_MULT_DOSStub_f02d {
  strings:
    $key_f02d = { a4 45 [2] d0 5d [2] 97 5f [2] d0 4e [2] 9e 42 [2] 92 48 [2] 85 43 [2] 9e 0d [2] a3 }

  condition:
    any of them
}
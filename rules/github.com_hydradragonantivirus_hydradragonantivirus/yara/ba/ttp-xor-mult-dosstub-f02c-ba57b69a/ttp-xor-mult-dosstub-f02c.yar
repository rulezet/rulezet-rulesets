rule TTP_XOR_MULT_DOSStub_f02c {
  strings:
    $key_f02c = { a4 44 [2] d0 5c [2] 97 5e [2] d0 4f [2] 9e 43 [2] 92 49 [2] 85 42 [2] 9e 0c [2] a3 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_f02e {
  strings:
    $key_f02e = { a4 46 [2] d0 5e [2] 97 5c [2] d0 4d [2] 9e 41 [2] 92 4b [2] 85 40 [2] 9e 0e [2] a3 }

  condition:
    any of them
}
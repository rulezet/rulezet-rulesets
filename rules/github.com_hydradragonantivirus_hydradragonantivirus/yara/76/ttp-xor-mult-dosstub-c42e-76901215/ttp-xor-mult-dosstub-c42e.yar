rule TTP_XOR_MULT_DOSStub_c42e {
  strings:
    $key_c42e = { 90 46 [2] e4 5e [2] a3 5c [2] e4 4d [2] aa 41 [2] a6 4b [2] b1 40 [2] aa 0e [2] 97 }

  condition:
    any of them
}
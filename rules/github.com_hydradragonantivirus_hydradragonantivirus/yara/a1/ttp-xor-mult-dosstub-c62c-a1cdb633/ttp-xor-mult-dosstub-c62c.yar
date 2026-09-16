rule TTP_XOR_MULT_DOSStub_c62c {
  strings:
    $key_c62c = { 92 44 [2] e6 5c [2] a1 5e [2] e6 4f [2] a8 43 [2] a4 49 [2] b3 42 [2] a8 0c [2] 95 }

  condition:
    any of them
}
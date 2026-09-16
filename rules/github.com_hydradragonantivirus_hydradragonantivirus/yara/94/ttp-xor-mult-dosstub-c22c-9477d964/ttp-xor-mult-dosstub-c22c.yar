rule TTP_XOR_MULT_DOSStub_c22c {
  strings:
    $key_c22c = { 96 44 [2] e2 5c [2] a5 5e [2] e2 4f [2] ac 43 [2] a0 49 [2] b7 42 [2] ac 0c [2] 91 }

  condition:
    any of them
}
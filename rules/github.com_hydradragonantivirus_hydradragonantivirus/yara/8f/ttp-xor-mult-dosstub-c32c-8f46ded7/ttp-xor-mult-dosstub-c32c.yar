rule TTP_XOR_MULT_DOSStub_c32c {
  strings:
    $key_c32c = { 97 44 [2] e3 5c [2] a4 5e [2] e3 4f [2] ad 43 [2] a1 49 [2] b6 42 [2] ad 0c [2] 90 }

  condition:
    any of them
}
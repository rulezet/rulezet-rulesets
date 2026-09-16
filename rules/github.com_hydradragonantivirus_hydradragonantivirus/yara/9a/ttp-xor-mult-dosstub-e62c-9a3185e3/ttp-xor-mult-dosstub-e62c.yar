rule TTP_XOR_MULT_DOSStub_e62c {
  strings:
    $key_e62c = { b2 44 [2] c6 5c [2] 81 5e [2] c6 4f [2] 88 43 [2] 84 49 [2] 93 42 [2] 88 0c [2] b5 }

  condition:
    any of them
}
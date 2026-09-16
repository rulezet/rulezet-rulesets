rule TTP_XOR_MULT_DOSStub_e32c {
  strings:
    $key_e32c = { b7 44 [2] c3 5c [2] 84 5e [2] c3 4f [2] 8d 43 [2] 81 49 [2] 96 42 [2] 8d 0c [2] b0 }

  condition:
    any of them
}
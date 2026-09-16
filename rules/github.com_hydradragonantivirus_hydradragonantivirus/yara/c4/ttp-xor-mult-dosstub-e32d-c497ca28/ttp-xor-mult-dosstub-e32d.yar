rule TTP_XOR_MULT_DOSStub_e32d {
  strings:
    $key_e32d = { b7 45 [2] c3 5d [2] 84 5f [2] c3 4e [2] 8d 42 [2] 81 48 [2] 96 43 [2] 8d 0d [2] b0 }

  condition:
    any of them
}
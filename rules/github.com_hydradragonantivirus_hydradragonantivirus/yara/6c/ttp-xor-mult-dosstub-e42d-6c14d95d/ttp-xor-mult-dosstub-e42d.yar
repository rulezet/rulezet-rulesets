rule TTP_XOR_MULT_DOSStub_e42d {
  strings:
    $key_e42d = { b0 45 [2] c4 5d [2] 83 5f [2] c4 4e [2] 8a 42 [2] 86 48 [2] 91 43 [2] 8a 0d [2] b7 }

  condition:
    any of them
}
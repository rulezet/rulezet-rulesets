rule TTP_XOR_MULT_DOSStub_e42c {
  strings:
    $key_e42c = { b0 44 [2] c4 5c [2] 83 5e [2] c4 4f [2] 8a 43 [2] 86 49 [2] 91 42 [2] 8a 0c [2] b7 }

  condition:
    any of them
}
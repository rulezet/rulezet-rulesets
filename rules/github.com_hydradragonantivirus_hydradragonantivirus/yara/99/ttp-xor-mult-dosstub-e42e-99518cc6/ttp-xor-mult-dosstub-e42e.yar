rule TTP_XOR_MULT_DOSStub_e42e {
  strings:
    $key_e42e = { b0 46 [2] c4 5e [2] 83 5c [2] c4 4d [2] 8a 41 [2] 86 4b [2] 91 40 [2] 8a 0e [2] b7 }

  condition:
    any of them
}
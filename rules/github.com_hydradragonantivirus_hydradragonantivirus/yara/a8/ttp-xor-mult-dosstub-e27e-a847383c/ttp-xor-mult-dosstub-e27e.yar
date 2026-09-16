rule TTP_XOR_MULT_DOSStub_e27e {
  strings:
    $key_e27e = { b6 16 [2] c2 0e [2] 85 0c [2] c2 1d [2] 8c 11 [2] 80 1b [2] 97 10 [2] 8c 5e [2] b1 }

  condition:
    any of them
}
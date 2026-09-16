rule TTP_XOR_MULT_DOSStub_e22e {
  strings:
    $key_e22e = { b6 46 [2] c2 5e [2] 85 5c [2] c2 4d [2] 8c 41 [2] 80 4b [2] 97 40 [2] 8c 0e [2] b1 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_e32e {
  strings:
    $key_e32e = { b7 46 [2] c3 5e [2] 84 5c [2] c3 4d [2] 8d 41 [2] 81 4b [2] 96 40 [2] 8d 0e [2] b0 }

  condition:
    any of them
}
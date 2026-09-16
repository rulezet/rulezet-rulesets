rule TTP_XOR_MULT_DOSStub_e77e {
  strings:
    $key_e77e = { b3 16 [2] c7 0e [2] 80 0c [2] c7 1d [2] 89 11 [2] 85 1b [2] 92 10 [2] 89 5e [2] b4 }

  condition:
    any of them
}
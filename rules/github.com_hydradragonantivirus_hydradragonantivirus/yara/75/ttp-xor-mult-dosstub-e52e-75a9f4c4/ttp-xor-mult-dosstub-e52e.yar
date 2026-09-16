rule TTP_XOR_MULT_DOSStub_e52e {
  strings:
    $key_e52e = { b1 46 [2] c5 5e [2] 82 5c [2] c5 4d [2] 8b 41 [2] 87 4b [2] 90 40 [2] 8b 0e [2] b6 }

  condition:
    any of them
}
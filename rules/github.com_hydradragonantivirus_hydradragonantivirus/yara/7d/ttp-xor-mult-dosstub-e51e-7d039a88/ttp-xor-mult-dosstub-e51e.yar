rule TTP_XOR_MULT_DOSStub_e51e {
  strings:
    $key_e51e = { b1 76 [2] c5 6e [2] 82 6c [2] c5 7d [2] 8b 71 [2] 87 7b [2] 90 70 [2] 8b 3e [2] b6 }

  condition:
    any of them
}
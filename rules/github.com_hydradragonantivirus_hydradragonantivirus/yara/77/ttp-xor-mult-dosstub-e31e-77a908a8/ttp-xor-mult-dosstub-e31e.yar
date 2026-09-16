rule TTP_XOR_MULT_DOSStub_e31e {
  strings:
    $key_e31e = { b7 76 [2] c3 6e [2] 84 6c [2] c3 7d [2] 8d 71 [2] 81 7b [2] 96 70 [2] 8d 3e [2] b0 }

  condition:
    any of them
}
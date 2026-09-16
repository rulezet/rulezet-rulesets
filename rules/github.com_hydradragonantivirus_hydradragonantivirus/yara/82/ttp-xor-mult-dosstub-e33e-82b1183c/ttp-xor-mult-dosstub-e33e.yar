rule TTP_XOR_MULT_DOSStub_e33e {
  strings:
    $key_e33e = { b7 56 [2] c3 4e [2] 84 4c [2] c3 5d [2] 8d 51 [2] 81 5b [2] 96 50 [2] 8d 1e [2] b0 }

  condition:
    any of them
}
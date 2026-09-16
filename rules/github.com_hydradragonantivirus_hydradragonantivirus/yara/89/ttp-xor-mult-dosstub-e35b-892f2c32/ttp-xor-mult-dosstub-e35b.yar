rule TTP_XOR_MULT_DOSStub_e35b {
  strings:
    $key_e35b = { b7 33 [2] c3 2b [2] 84 29 [2] c3 38 [2] 8d 34 [2] 81 3e [2] 96 35 [2] 8d 7b [2] b0 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_e34b {
  strings:
    $key_e34b = { b7 23 [2] c3 3b [2] 84 39 [2] c3 28 [2] 8d 24 [2] 81 2e [2] 96 25 [2] 8d 6b [2] b0 }

  condition:
    any of them
}
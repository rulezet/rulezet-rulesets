rule TTP_XOR_MULT_DOSStub_e34c {
  strings:
    $key_e34c = { b7 24 [2] c3 3c [2] 84 3e [2] c3 2f [2] 8d 23 [2] 81 29 [2] 96 22 [2] 8d 6c [2] b0 }

  condition:
    any of them
}
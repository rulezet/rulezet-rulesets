rule TTP_XOR_MULT_DOSStub_e3e7 {
  strings:
    $key_e3e7 = { b7 8f [2] c3 97 [2] 84 95 [2] c3 84 [2] 8d 88 [2] 81 82 [2] 96 89 [2] 8d c7 [2] b0 }

  condition:
    any of them
}
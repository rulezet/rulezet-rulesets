rule TTP_XOR_MULT_DOSStub_14f0 {
  strings:
    $key_14f0 = { 40 98 [2] 34 80 [2] 73 82 [2] 34 93 [2] 7a 9f [2] 76 95 [2] 61 9e [2] 7a d0 [2] 47 }

  condition:
    any of them
}
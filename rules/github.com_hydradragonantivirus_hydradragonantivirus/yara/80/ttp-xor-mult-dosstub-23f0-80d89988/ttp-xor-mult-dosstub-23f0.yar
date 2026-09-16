rule TTP_XOR_MULT_DOSStub_23f0 {
  strings:
    $key_23f0 = { 77 98 [2] 03 80 [2] 44 82 [2] 03 93 [2] 4d 9f [2] 41 95 [2] 56 9e [2] 4d d0 [2] 70 }

  condition:
    any of them
}
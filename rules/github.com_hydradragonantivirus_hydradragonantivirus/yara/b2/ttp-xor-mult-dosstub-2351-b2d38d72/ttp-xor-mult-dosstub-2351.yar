rule TTP_XOR_MULT_DOSStub_2351 {
  strings:
    $key_2351 = { 77 39 [2] 03 21 [2] 44 23 [2] 03 32 [2] 4d 3e [2] 41 34 [2] 56 3f [2] 4d 71 [2] 70 }

  condition:
    any of them
}
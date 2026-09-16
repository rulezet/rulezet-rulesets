rule TTP_XOR_MULT_DOSStub_c526 {
  strings:
    $key_c526 = { 91 4e [2] e5 56 [2] a2 54 [2] e5 45 [2] ab 49 [2] a7 43 [2] b0 48 [2] ab 06 [2] 96 }

  condition:
    any of them
}
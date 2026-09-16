rule TTP_XOR_MULT_DOSStub_33e1 {
  strings:
    $key_33e1 = { 67 89 [2] 13 91 [2] 54 93 [2] 13 82 [2] 5d 8e [2] 51 84 [2] 46 8f [2] 5d c1 [2] 60 }

  condition:
    any of them
}
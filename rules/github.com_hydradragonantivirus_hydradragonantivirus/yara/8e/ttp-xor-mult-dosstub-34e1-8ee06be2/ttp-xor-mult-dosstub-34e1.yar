rule TTP_XOR_MULT_DOSStub_34e1 {
  strings:
    $key_34e1 = { 60 89 [2] 14 91 [2] 53 93 [2] 14 82 [2] 5a 8e [2] 56 84 [2] 41 8f [2] 5a c1 [2] 67 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_34f0 {
  strings:
    $key_34f0 = { 60 98 [2] 14 80 [2] 53 82 [2] 14 93 [2] 5a 9f [2] 56 95 [2] 41 9e [2] 5a d0 [2] 67 }

  condition:
    any of them
}
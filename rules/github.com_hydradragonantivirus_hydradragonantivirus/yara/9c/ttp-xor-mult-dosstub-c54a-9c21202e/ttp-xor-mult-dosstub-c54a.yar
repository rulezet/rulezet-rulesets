rule TTP_XOR_MULT_DOSStub_c54a {
  strings:
    $key_c54a = { 91 22 [2] e5 3a [2] a2 38 [2] e5 29 [2] ab 25 [2] a7 2f [2] b0 24 [2] ab 6a [2] 96 }

  condition:
    any of them
}
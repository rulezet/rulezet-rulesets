rule TTP_XOR_MULT_DOSStub_c53a {
  strings:
    $key_c53a = { 91 52 [2] e5 4a [2] a2 48 [2] e5 59 [2] ab 55 [2] a7 5f [2] b0 54 [2] ab 1a [2] 96 }

  condition:
    any of them
}
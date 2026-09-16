rule TTP_XOR_MULT_DOSStub_c51a {
  strings:
    $key_c51a = { 91 72 [2] e5 6a [2] a2 68 [2] e5 79 [2] ab 75 [2] a7 7f [2] b0 74 [2] ab 3a [2] 96 }

  condition:
    any of them
}
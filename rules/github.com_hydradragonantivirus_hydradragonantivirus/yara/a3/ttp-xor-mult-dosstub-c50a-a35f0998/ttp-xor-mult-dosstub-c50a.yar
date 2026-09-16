rule TTP_XOR_MULT_DOSStub_c50a {
  strings:
    $key_c50a = { 91 62 [2] e5 7a [2] a2 78 [2] e5 69 [2] ab 65 [2] a7 6f [2] b0 64 [2] ab 2a [2] 96 }

  condition:
    any of them
}
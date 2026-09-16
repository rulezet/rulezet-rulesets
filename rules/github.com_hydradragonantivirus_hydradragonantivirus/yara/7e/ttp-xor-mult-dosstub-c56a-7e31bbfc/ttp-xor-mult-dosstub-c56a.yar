rule TTP_XOR_MULT_DOSStub_c56a {
  strings:
    $key_c56a = { 91 02 [2] e5 1a [2] a2 18 [2] e5 09 [2] ab 05 [2] a7 0f [2] b0 04 [2] ab 4a [2] 96 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_c53b {
  strings:
    $key_c53b = { 91 53 [2] e5 4b [2] a2 49 [2] e5 58 [2] ab 54 [2] a7 5e [2] b0 55 [2] ab 1b [2] 96 }

  condition:
    any of them
}
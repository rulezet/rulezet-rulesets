rule TTP_XOR_MULT_DOSStub_c53d {
  strings:
    $key_c53d = { 91 55 [2] e5 4d [2] a2 4f [2] e5 5e [2] ab 52 [2] a7 58 [2] b0 53 [2] ab 1d [2] 96 }

  condition:
    any of them
}
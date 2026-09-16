rule TTP_XOR_MULT_DOSStub_c500 {
  strings:
    $key_c500 = { 91 68 [2] e5 70 [2] a2 72 [2] e5 63 [2] ab 6f [2] a7 65 [2] b0 6e [2] ab 20 [2] 96 }

  condition:
    any of them
}
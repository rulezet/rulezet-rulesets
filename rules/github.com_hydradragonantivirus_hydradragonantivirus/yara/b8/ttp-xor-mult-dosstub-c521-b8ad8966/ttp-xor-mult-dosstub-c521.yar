rule TTP_XOR_MULT_DOSStub_c521 {
  strings:
    $key_c521 = { 91 49 [2] e5 51 [2] a2 53 [2] e5 42 [2] ab 4e [2] a7 44 [2] b0 4f [2] ab 01 [2] 96 }

  condition:
    any of them
}
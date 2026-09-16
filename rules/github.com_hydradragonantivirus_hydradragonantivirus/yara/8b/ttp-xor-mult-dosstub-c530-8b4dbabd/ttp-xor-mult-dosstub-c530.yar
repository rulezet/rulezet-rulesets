rule TTP_XOR_MULT_DOSStub_c530 {
  strings:
    $key_c530 = { 91 58 [2] e5 40 [2] a2 42 [2] e5 53 [2] ab 5f [2] a7 55 [2] b0 5e [2] ab 10 [2] 96 }

  condition:
    any of them
}
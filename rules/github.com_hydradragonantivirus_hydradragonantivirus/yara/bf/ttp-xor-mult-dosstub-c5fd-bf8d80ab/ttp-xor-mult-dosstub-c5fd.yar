rule TTP_XOR_MULT_DOSStub_c5fd {
  strings:
    $key_c5fd = { 91 95 [2] e5 8d [2] a2 8f [2] e5 9e [2] ab 92 [2] a7 98 [2] b0 93 [2] ab dd [2] 96 }

  condition:
    any of them
}
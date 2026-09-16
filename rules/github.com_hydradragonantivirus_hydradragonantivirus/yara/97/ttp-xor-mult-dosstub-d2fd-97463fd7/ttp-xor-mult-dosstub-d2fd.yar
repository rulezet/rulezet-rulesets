rule TTP_XOR_MULT_DOSStub_d2fd {
  strings:
    $key_d2fd = { 86 95 [2] f2 8d [2] b5 8f [2] f2 9e [2] bc 92 [2] b0 98 [2] a7 93 [2] bc dd [2] 81 }

  condition:
    any of them
}
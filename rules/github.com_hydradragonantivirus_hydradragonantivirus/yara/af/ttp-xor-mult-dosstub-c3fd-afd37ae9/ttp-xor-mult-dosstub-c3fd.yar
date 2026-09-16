rule TTP_XOR_MULT_DOSStub_c3fd {
  strings:
    $key_c3fd = { 97 95 [2] e3 8d [2] a4 8f [2] e3 9e [2] ad 92 [2] a1 98 [2] b6 93 [2] ad dd [2] 90 }

  condition:
    any of them
}
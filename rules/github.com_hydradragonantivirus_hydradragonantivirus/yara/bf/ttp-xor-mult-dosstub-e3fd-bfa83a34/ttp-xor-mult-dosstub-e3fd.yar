rule TTP_XOR_MULT_DOSStub_e3fd {
  strings:
    $key_e3fd = { b7 95 [2] c3 8d [2] 84 8f [2] c3 9e [2] 8d 92 [2] 81 98 [2] 96 93 [2] 8d dd [2] b0 }

  condition:
    any of them
}
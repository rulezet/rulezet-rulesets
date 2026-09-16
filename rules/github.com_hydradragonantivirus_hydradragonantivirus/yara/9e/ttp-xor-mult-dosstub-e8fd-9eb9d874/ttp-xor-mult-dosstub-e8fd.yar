rule TTP_XOR_MULT_DOSStub_e8fd {
  strings:
    $key_e8fd = { bc 95 [2] c8 8d [2] 8f 8f [2] c8 9e [2] 86 92 [2] 8a 98 [2] 9d 93 [2] 86 dd [2] bb }

  condition:
    any of them
}
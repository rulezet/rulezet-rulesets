rule TTP_XOR_MULT_DOSStub_78fd {
  strings:
    $key_78fd = { 2c 95 [2] 58 8d [2] 1f 8f [2] 58 9e [2] 16 92 [2] 1a 98 [2] 0d 93 [2] 16 dd [2] 2b }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_42fd {
  strings:
    $key_42fd = { 16 95 [2] 62 8d [2] 25 8f [2] 62 9e [2] 2c 92 [2] 20 98 [2] 37 93 [2] 2c dd [2] 11 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_55fd {
  strings:
    $key_55fd = { 01 95 [2] 75 8d [2] 32 8f [2] 75 9e [2] 3b 92 [2] 37 98 [2] 20 93 [2] 3b dd [2] 06 }

  condition:
    any of them
}
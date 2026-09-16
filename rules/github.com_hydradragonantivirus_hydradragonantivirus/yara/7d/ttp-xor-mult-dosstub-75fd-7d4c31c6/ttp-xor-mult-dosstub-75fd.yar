rule TTP_XOR_MULT_DOSStub_75fd {
  strings:
    $key_75fd = { 21 95 [2] 55 8d [2] 12 8f [2] 55 9e [2] 1b 92 [2] 17 98 [2] 00 93 [2] 1b dd [2] 26 }

  condition:
    any of them
}
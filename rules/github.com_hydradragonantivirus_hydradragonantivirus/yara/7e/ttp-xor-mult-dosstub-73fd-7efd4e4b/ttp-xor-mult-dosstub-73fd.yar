rule TTP_XOR_MULT_DOSStub_73fd {
  strings:
    $key_73fd = { 27 95 [2] 53 8d [2] 14 8f [2] 53 9e [2] 1d 92 [2] 11 98 [2] 06 93 [2] 1d dd [2] 20 }

  condition:
    any of them
}
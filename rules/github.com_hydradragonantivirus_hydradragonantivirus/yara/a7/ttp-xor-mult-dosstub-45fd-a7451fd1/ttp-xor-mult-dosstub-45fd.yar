rule TTP_XOR_MULT_DOSStub_45fd {
  strings:
    $key_45fd = { 11 95 [2] 65 8d [2] 22 8f [2] 65 9e [2] 2b 92 [2] 27 98 [2] 30 93 [2] 2b dd [2] 16 }

  condition:
    any of them
}
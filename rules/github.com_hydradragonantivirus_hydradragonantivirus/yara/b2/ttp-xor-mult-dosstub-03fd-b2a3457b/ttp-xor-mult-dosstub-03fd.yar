rule TTP_XOR_MULT_DOSStub_03fd {
  strings:
    $key_03fd = { 57 95 [2] 23 8d [2] 64 8f [2] 23 9e [2] 6d 92 [2] 61 98 [2] 76 93 [2] 6d dd [2] 50 }

  condition:
    any of them
}
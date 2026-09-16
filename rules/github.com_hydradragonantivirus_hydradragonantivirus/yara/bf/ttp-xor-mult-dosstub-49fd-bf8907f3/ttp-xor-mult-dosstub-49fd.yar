rule TTP_XOR_MULT_DOSStub_49fd {
  strings:
    $key_49fd = { 1d 95 [2] 69 8d [2] 2e 8f [2] 69 9e [2] 27 92 [2] 2b 98 [2] 3c 93 [2] 27 dd [2] 1a }

  condition:
    any of them
}
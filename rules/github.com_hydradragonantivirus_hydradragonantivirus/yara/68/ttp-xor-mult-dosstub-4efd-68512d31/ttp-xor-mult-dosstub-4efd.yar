rule TTP_XOR_MULT_DOSStub_4efd {
  strings:
    $key_4efd = { 1a 95 [2] 6e 8d [2] 29 8f [2] 6e 9e [2] 20 92 [2] 2c 98 [2] 3b 93 [2] 20 dd [2] 1d }

  condition:
    any of them
}
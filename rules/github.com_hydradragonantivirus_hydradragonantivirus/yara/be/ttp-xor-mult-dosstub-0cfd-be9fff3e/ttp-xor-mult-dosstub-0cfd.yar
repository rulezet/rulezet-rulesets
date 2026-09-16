rule TTP_XOR_MULT_DOSStub_0cfd {
  strings:
    $key_0cfd = { 58 95 [2] 2c 8d [2] 6b 8f [2] 2c 9e [2] 62 92 [2] 6e 98 [2] 79 93 [2] 62 dd [2] 5f }

  condition:
    any of them
}
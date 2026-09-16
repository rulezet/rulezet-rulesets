rule TTP_XOR_MULT_DOSStub_2cfd {
  strings:
    $key_2cfd = { 78 95 [2] 0c 8d [2] 4b 8f [2] 0c 9e [2] 42 92 [2] 4e 98 [2] 59 93 [2] 42 dd [2] 7f }

  condition:
    any of them
}
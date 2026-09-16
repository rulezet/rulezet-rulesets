rule TTP_XOR_MULT_DOSStub_7cfd {
  strings:
    $key_7cfd = { 28 95 [2] 5c 8d [2] 1b 8f [2] 5c 9e [2] 12 92 [2] 1e 98 [2] 09 93 [2] 12 dd [2] 2f }

  condition:
    any of them
}
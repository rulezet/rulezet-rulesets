rule TTP_XOR_MULT_DOSStub_3efd {
  strings:
    $key_3efd = { 6a 95 [2] 1e 8d [2] 59 8f [2] 1e 9e [2] 50 92 [2] 5c 98 [2] 4b 93 [2] 50 dd [2] 6d }

  condition:
    any of them
}
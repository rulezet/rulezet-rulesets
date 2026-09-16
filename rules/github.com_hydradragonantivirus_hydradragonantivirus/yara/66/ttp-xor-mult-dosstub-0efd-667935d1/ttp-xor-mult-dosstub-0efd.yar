rule TTP_XOR_MULT_DOSStub_0efd {
  strings:
    $key_0efd = { 5a 95 [2] 2e 8d [2] 69 8f [2] 2e 9e [2] 60 92 [2] 6c 98 [2] 7b 93 [2] 60 dd [2] 5d }

  condition:
    any of them
}
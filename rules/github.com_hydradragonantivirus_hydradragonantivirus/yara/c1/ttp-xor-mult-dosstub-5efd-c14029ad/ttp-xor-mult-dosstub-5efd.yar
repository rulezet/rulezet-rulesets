rule TTP_XOR_MULT_DOSStub_5efd {
  strings:
    $key_5efd = { 0a 95 [2] 7e 8d [2] 39 8f [2] 7e 9e [2] 30 92 [2] 3c 98 [2] 2b 93 [2] 30 dd [2] 0d }

  condition:
    any of them
}
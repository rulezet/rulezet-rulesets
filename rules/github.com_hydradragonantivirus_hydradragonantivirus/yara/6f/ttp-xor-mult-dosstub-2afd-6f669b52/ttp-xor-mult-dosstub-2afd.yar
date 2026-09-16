rule TTP_XOR_MULT_DOSStub_2afd {
  strings:
    $key_2afd = { 7e 95 [2] 0a 8d [2] 4d 8f [2] 0a 9e [2] 44 92 [2] 48 98 [2] 5f 93 [2] 44 dd [2] 79 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_1afd {
  strings:
    $key_1afd = { 4e 95 [2] 3a 8d [2] 7d 8f [2] 3a 9e [2] 74 92 [2] 78 98 [2] 6f 93 [2] 74 dd [2] 49 }

  condition:
    any of them
}
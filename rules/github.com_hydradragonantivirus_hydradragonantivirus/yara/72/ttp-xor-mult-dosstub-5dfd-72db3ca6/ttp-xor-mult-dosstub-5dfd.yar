rule TTP_XOR_MULT_DOSStub_5dfd {
  strings:
    $key_5dfd = { 09 95 [2] 7d 8d [2] 3a 8f [2] 7d 9e [2] 33 92 [2] 3f 98 [2] 28 93 [2] 33 dd [2] 0e }

  condition:
    any of them
}
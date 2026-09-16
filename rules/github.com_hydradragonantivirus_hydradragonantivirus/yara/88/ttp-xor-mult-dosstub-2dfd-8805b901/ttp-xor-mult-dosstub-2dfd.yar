rule TTP_XOR_MULT_DOSStub_2dfd {
  strings:
    $key_2dfd = { 79 95 [2] 0d 8d [2] 4a 8f [2] 0d 9e [2] 43 92 [2] 4f 98 [2] 58 93 [2] 43 dd [2] 7e }

  condition:
    any of them
}
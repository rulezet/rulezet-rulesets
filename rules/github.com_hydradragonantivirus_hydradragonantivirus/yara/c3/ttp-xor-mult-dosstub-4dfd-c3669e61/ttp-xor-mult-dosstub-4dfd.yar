rule TTP_XOR_MULT_DOSStub_4dfd {
  strings:
    $key_4dfd = { 19 95 [2] 6d 8d [2] 2a 8f [2] 6d 9e [2] 23 92 [2] 2f 98 [2] 38 93 [2] 23 dd [2] 1e }

  condition:
    any of them
}
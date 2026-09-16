rule TTP_XOR_MULT_DOSStub_7dfd {
  strings:
    $key_7dfd = { 29 95 [2] 5d 8d [2] 1a 8f [2] 5d 9e [2] 13 92 [2] 1f 98 [2] 08 93 [2] 13 dd [2] 2e }

  condition:
    any of them
}
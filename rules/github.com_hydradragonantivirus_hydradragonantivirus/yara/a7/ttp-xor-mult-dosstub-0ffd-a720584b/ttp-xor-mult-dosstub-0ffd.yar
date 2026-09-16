rule TTP_XOR_MULT_DOSStub_0ffd {
  strings:
    $key_0ffd = { 5b 95 [2] 2f 8d [2] 68 8f [2] 2f 9e [2] 61 92 [2] 6d 98 [2] 7a 93 [2] 61 dd [2] 5c }

  condition:
    any of them
}
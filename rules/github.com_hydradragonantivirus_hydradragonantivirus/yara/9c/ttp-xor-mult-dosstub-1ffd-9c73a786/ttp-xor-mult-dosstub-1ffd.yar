rule TTP_XOR_MULT_DOSStub_1ffd {
  strings:
    $key_1ffd = { 4b 95 [2] 3f 8d [2] 78 8f [2] 3f 9e [2] 71 92 [2] 7d 98 [2] 6a 93 [2] 71 dd [2] 4c }

  condition:
    any of them
}
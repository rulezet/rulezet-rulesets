rule TTP_XOR_MULT_DOSStub_2ffd {
  strings:
    $key_2ffd = { 7b 95 [2] 0f 8d [2] 48 8f [2] 0f 9e [2] 41 92 [2] 4d 98 [2] 5a 93 [2] 41 dd [2] 7c }

  condition:
    any of them
}
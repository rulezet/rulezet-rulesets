rule TTP_XOR_MULT_DOSStub_0afd {
  strings:
    $key_0afd = { 5e 95 [2] 2a 8d [2] 6d 8f [2] 2a 9e [2] 64 92 [2] 68 98 [2] 7f 93 [2] 64 dd [2] 59 }

  condition:
    any of them
}
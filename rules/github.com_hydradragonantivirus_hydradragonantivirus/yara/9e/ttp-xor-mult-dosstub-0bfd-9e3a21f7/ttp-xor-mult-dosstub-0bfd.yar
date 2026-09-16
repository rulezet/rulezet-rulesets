rule TTP_XOR_MULT_DOSStub_0bfd {
  strings:
    $key_0bfd = { 5f 95 [2] 2b 8d [2] 6c 8f [2] 2b 9e [2] 65 92 [2] 69 98 [2] 7e 93 [2] 65 dd [2] 58 }

  condition:
    any of them
}
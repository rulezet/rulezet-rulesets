rule TTP_XOR_MULT_DOSStub_4bfd {
  strings:
    $key_4bfd = { 1f 95 [2] 6b 8d [2] 2c 8f [2] 6b 9e [2] 25 92 [2] 29 98 [2] 3e 93 [2] 25 dd [2] 18 }

  condition:
    any of them
}
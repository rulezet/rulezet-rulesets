rule TTP_XOR_MULT_DOSStub_2bfd {
  strings:
    $key_2bfd = { 7f 95 [2] 0b 8d [2] 4c 8f [2] 0b 9e [2] 45 92 [2] 49 98 [2] 5e 93 [2] 45 dd [2] 78 }

  condition:
    any of them
}
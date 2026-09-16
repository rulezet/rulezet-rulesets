rule TTP_XOR_MULT_DOSStub_6bfd {
  strings:
    $key_6bfd = { 3f 95 [2] 4b 8d [2] 0c 8f [2] 4b 9e [2] 05 92 [2] 09 98 [2] 1e 93 [2] 05 dd [2] 38 }

  condition:
    any of them
}
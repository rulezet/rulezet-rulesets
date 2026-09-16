rule TTP_XOR_MULT_DOSStub_7bfd {
  strings:
    $key_7bfd = { 2f 95 [2] 5b 8d [2] 1c 8f [2] 5b 9e [2] 15 92 [2] 19 98 [2] 0e 93 [2] 15 dd [2] 28 }

  condition:
    any of them
}
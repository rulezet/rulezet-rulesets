rule TTP_XOR_MULT_DOSStub_3cfd {
  strings:
    $key_3cfd = { 68 95 [2] 1c 8d [2] 5b 8f [2] 1c 9e [2] 52 92 [2] 5e 98 [2] 49 93 [2] 52 dd [2] 6f }

  condition:
    any of them
}
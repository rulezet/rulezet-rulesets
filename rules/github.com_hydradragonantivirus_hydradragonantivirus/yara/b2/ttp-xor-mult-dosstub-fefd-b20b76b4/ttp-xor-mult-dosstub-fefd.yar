rule TTP_XOR_MULT_DOSStub_fefd {
  strings:
    $key_fefd = { aa 95 [2] de 8d [2] 99 8f [2] de 9e [2] 90 92 [2] 9c 98 [2] 8b 93 [2] 90 dd [2] ad }

  condition:
    any of them
}
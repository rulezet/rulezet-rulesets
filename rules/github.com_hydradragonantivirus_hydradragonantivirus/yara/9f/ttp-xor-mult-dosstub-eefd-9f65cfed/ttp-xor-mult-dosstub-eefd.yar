rule TTP_XOR_MULT_DOSStub_eefd {
  strings:
    $key_eefd = { ba 95 [2] ce 8d [2] 89 8f [2] ce 9e [2] 80 92 [2] 8c 98 [2] 9b 93 [2] 80 dd [2] bd }

  condition:
    any of them
}
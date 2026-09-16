rule TTP_XOR_MULT_DOSStub_edfd {
  strings:
    $key_edfd = { b9 95 [2] cd 8d [2] 8a 8f [2] cd 9e [2] 83 92 [2] 8f 98 [2] 98 93 [2] 83 dd [2] be }

  condition:
    any of them
}
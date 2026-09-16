rule TTP_XOR_MULT_DOSStub_edb5 {
  strings:
    $key_edb5 = { b9 dd [2] cd c5 [2] 8a c7 [2] cd d6 [2] 83 da [2] 8f d0 [2] 98 db [2] 83 95 [2] be }

  condition:
    any of them
}
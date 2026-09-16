rule TTP_XOR_MULT_DOSStub_edfa {
  strings:
    $key_edfa = { b9 92 [2] cd 8a [2] 8a 88 [2] cd 99 [2] 83 95 [2] 8f 9f [2] 98 94 [2] 83 da [2] be }

  condition:
    any of them
}
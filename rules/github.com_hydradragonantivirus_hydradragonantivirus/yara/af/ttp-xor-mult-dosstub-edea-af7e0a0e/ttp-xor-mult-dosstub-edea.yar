rule TTP_XOR_MULT_DOSStub_edea {
  strings:
    $key_edea = { b9 82 [2] cd 9a [2] 8a 98 [2] cd 89 [2] 83 85 [2] 8f 8f [2] 98 84 [2] 83 ca [2] be }

  condition:
    any of them
}
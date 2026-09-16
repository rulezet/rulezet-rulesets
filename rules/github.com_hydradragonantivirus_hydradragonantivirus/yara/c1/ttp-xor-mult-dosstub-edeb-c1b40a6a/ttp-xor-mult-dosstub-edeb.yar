rule TTP_XOR_MULT_DOSStub_edeb {
  strings:
    $key_edeb = { b9 83 [2] cd 9b [2] 8a 99 [2] cd 88 [2] 83 84 [2] 8f 8e [2] 98 85 [2] 83 cb [2] be }

  condition:
    any of them
}
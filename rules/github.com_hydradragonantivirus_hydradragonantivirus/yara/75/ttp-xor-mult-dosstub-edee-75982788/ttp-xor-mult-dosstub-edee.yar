rule TTP_XOR_MULT_DOSStub_edee {
  strings:
    $key_edee = { b9 86 [2] cd 9e [2] 8a 9c [2] cd 8d [2] 83 81 [2] 8f 8b [2] 98 80 [2] 83 ce [2] be }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_eddb {
  strings:
    $key_eddb = { b9 b3 [2] cd ab [2] 8a a9 [2] cd b8 [2] 83 b4 [2] 8f be [2] 98 b5 [2] 83 fb [2] be }

  condition:
    any of them
}
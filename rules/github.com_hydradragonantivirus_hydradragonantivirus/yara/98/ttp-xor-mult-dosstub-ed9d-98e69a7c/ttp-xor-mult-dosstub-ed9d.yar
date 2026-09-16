rule TTP_XOR_MULT_DOSStub_ed9d {
  strings:
    $key_ed9d = { b9 f5 [2] cd ed [2] 8a ef [2] cd fe [2] 83 f2 [2] 8f f8 [2] 98 f3 [2] 83 bd [2] be }

  condition:
    any of them
}
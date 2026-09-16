rule TTP_XOR_MULT_DOSStub_ed9f {
  strings:
    $key_ed9f = { b9 f7 [2] cd ef [2] 8a ed [2] cd fc [2] 83 f0 [2] 8f fa [2] 98 f1 [2] 83 bf [2] be }

  condition:
    any of them
}
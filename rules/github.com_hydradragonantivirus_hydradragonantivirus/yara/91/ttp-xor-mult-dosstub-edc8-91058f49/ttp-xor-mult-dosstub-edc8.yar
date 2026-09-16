rule TTP_XOR_MULT_DOSStub_edc8 {
  strings:
    $key_edc8 = { b9 a0 [2] cd b8 [2] 8a ba [2] cd ab [2] 83 a7 [2] 8f ad [2] 98 a6 [2] 83 e8 [2] be }

  condition:
    any of them
}
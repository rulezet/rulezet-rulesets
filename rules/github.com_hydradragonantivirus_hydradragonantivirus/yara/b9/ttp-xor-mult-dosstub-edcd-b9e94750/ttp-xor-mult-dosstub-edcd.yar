rule TTP_XOR_MULT_DOSStub_edcd {
  strings:
    $key_edcd = { b9 a5 [2] cd bd [2] 8a bf [2] cd ae [2] 83 a2 [2] 8f a8 [2] 98 a3 [2] 83 ed [2] be }

  condition:
    any of them
}
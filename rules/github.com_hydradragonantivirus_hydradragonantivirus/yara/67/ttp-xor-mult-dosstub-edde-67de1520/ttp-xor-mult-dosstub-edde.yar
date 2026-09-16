rule TTP_XOR_MULT_DOSStub_edde {
  strings:
    $key_edde = { b9 b6 [2] cd ae [2] 8a ac [2] cd bd [2] 83 b1 [2] 8f bb [2] 98 b0 [2] 83 fe [2] be }

  condition:
    any of them
}
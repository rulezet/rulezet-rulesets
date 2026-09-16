rule TTP_XOR_MULT_DOSStub_cbce {
  strings:
    $key_cbce = { 9f a6 [2] eb be [2] ac bc [2] eb ad [2] a5 a1 [2] a9 ab [2] be a0 [2] a5 ee [2] 98 }

  condition:
    any of them
}
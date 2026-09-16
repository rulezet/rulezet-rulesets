rule TTP_XOR_MULT_DOSStub_b893 {
  strings:
    $key_b893 = { ec fb [2] 98 e3 [2] df e1 [2] 98 f0 [2] d6 fc [2] da f6 [2] cd fd [2] d6 b3 [2] eb }

  condition:
    any of them
}
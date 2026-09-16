rule TTP_XOR_MULT_DOSStub_ed93 {
  strings:
    $key_ed93 = { b9 fb [2] cd e3 [2] 8a e1 [2] cd f0 [2] 83 fc [2] 8f f6 [2] 98 fd [2] 83 b3 [2] be }

  condition:
    any of them
}
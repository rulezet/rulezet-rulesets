rule TTP_XOR_MULT_DOSStub_ed95 {
  strings:
    $key_ed95 = { b9 fd [2] cd e5 [2] 8a e7 [2] cd f6 [2] 83 fa [2] 8f f0 [2] 98 fb [2] 83 b5 [2] be }

  condition:
    any of them
}
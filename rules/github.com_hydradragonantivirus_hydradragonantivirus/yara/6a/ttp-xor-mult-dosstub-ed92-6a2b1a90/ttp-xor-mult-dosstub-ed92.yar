rule TTP_XOR_MULT_DOSStub_ed92 {
  strings:
    $key_ed92 = { b9 fa [2] cd e2 [2] 8a e0 [2] cd f1 [2] 83 fd [2] 8f f7 [2] 98 fc [2] 83 b2 [2] be }

  condition:
    any of them
}
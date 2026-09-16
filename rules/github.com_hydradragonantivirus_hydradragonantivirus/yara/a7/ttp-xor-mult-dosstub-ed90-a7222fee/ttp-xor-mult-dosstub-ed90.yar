rule TTP_XOR_MULT_DOSStub_ed90 {
  strings:
    $key_ed90 = { b9 f8 [2] cd e0 [2] 8a e2 [2] cd f3 [2] 83 ff [2] 8f f5 [2] 98 fe [2] 83 b0 [2] be }

  condition:
    any of them
}
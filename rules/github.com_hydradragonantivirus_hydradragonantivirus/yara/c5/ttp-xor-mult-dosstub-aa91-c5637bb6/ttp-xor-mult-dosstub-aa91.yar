rule TTP_XOR_MULT_DOSStub_aa91 {
  strings:
    $key_aa91 = { fe f9 [2] 8a e1 [2] cd e3 [2] 8a f2 [2] c4 fe [2] c8 f4 [2] df ff [2] c4 b1 [2] f9 }

  condition:
    any of them
}
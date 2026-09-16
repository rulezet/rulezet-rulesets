rule TTP_XOR_MULT_DOSStub_aa86 {
  strings:
    $key_aa86 = { fe ee [2] 8a f6 [2] cd f4 [2] 8a e5 [2] c4 e9 [2] c8 e3 [2] df e8 [2] c4 a6 [2] f9 }

  condition:
    any of them
}
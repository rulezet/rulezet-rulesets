rule TTP_XOR_MULT_DOSStub_eda8 {
  strings:
    $key_eda8 = { b9 c0 [2] cd d8 [2] 8a da [2] cd cb [2] 83 c7 [2] 8f cd [2] 98 c6 [2] 83 88 [2] be }

  condition:
    any of them
}
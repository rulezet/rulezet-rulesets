rule TTP_XOR_MULT_DOSStub_5da8 {
  strings:
    $key_5da8 = { 09 c0 [2] 7d d8 [2] 3a da [2] 7d cb [2] 33 c7 [2] 3f cd [2] 28 c6 [2] 33 88 [2] 0e }

  condition:
    any of them
}
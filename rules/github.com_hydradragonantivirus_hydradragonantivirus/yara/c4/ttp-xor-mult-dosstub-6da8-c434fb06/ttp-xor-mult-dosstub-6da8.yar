rule TTP_XOR_MULT_DOSStub_6da8 {
  strings:
    $key_6da8 = { 39 c0 [2] 4d d8 [2] 0a da [2] 4d cb [2] 03 c7 [2] 0f cd [2] 18 c6 [2] 03 88 [2] 3e }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_2ddd {
  strings:
    $key_2ddd = { 79 b5 [2] 0d ad [2] 4a af [2] 0d be [2] 43 b2 [2] 4f b8 [2] 58 b3 [2] 43 fd [2] 7e }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_6ddd {
  strings:
    $key_6ddd = { 39 b5 [2] 4d ad [2] 0a af [2] 4d be [2] 03 b2 [2] 0f b8 [2] 18 b3 [2] 03 fd [2] 3e }

  condition:
    any of them
}
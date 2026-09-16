rule TTP_XOR_MULT_DOSStub_1ddd {
  strings:
    $key_1ddd = { 49 b5 [2] 3d ad [2] 7a af [2] 3d be [2] 73 b2 [2] 7f b8 [2] 68 b3 [2] 73 fd [2] 4e }

  condition:
    any of them
}
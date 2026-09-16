rule TTP_XOR_MULT_DOSStub_3ddd {
  strings:
    $key_3ddd = { 69 b5 [2] 1d ad [2] 5a af [2] 1d be [2] 53 b2 [2] 5f b8 [2] 48 b3 [2] 53 fd [2] 6e }

  condition:
    any of them
}
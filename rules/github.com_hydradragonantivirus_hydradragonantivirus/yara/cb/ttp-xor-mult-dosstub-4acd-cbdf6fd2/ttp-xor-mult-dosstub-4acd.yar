rule TTP_XOR_MULT_DOSStub_4acd {
  strings:
    $key_4acd = { 1e a5 [2] 6a bd [2] 2d bf [2] 6a ae [2] 24 a2 [2] 28 a8 [2] 3f a3 [2] 24 ed [2] 19 }

  condition:
    any of them
}
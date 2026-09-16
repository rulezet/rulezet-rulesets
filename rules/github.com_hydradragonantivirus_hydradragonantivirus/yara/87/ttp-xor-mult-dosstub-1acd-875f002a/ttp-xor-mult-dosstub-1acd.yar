rule TTP_XOR_MULT_DOSStub_1acd {
  strings:
    $key_1acd = { 4e a5 [2] 3a bd [2] 7d bf [2] 3a ae [2] 74 a2 [2] 78 a8 [2] 6f a3 [2] 74 ed [2] 49 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_2acd {
  strings:
    $key_2acd = { 7e a5 [2] 0a bd [2] 4d bf [2] 0a ae [2] 44 a2 [2] 48 a8 [2] 5f a3 [2] 44 ed [2] 79 }

  condition:
    any of them
}
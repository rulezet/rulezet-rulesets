rule TTP_XOR_MULT_DOSStub_3acd {
  strings:
    $key_3acd = { 6e a5 [2] 1a bd [2] 5d bf [2] 1a ae [2] 54 a2 [2] 58 a8 [2] 4f a3 [2] 54 ed [2] 69 }

  condition:
    any of them
}
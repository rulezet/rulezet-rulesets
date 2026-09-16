rule TTP_XOR_MULT_DOSStub_5dcd {
  strings:
    $key_5dcd = { 09 a5 [2] 7d bd [2] 3a bf [2] 7d ae [2] 33 a2 [2] 3f a8 [2] 28 a3 [2] 33 ed [2] 0e }

  condition:
    any of them
}
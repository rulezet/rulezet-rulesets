rule TTP_XOR_MULT_DOSStub_4dcd {
  strings:
    $key_4dcd = { 19 a5 [2] 6d bd [2] 2a bf [2] 6d ae [2] 23 a2 [2] 2f a8 [2] 38 a3 [2] 23 ed [2] 1e }

  condition:
    any of them
}
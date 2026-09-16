rule TTP_XOR_MULT_DOSStub_6dcd {
  strings:
    $key_6dcd = { 39 a5 [2] 4d bd [2] 0a bf [2] 4d ae [2] 03 a2 [2] 0f a8 [2] 18 a3 [2] 03 ed [2] 3e }

  condition:
    any of them
}
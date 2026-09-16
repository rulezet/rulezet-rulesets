rule TTP_XOR_MULT_DOSStub_3d5b {
  strings:
    $key_3d5b = { 69 33 [2] 1d 2b [2] 5a 29 [2] 1d 38 [2] 53 34 [2] 5f 3e [2] 48 35 [2] 53 7b [2] 6e }

  condition:
    any of them
}
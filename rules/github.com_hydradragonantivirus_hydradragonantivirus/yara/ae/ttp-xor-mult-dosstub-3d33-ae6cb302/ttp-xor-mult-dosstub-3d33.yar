rule TTP_XOR_MULT_DOSStub_3d33 {
  strings:
    $key_3d33 = { 69 5b [2] 1d 43 [2] 5a 41 [2] 1d 50 [2] 53 5c [2] 5f 56 [2] 48 5d [2] 53 13 [2] 6e }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_3d53 {
  strings:
    $key_3d53 = { 69 3b [2] 1d 23 [2] 5a 21 [2] 1d 30 [2] 53 3c [2] 5f 36 [2] 48 3d [2] 53 73 [2] 6e }

  condition:
    any of them
}
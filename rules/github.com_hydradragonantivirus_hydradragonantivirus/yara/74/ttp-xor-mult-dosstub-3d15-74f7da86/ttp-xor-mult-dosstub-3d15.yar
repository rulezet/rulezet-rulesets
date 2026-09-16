rule TTP_XOR_MULT_DOSStub_3d15 {
  strings:
    $key_3d15 = { 69 7d [2] 1d 65 [2] 5a 67 [2] 1d 76 [2] 53 7a [2] 5f 70 [2] 48 7b [2] 53 35 [2] 6e }

  condition:
    any of them
}
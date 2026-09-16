rule TTP_XOR_MULT_DOSStub_3d78 {
  strings:
    $key_3d78 = { 69 10 [2] 1d 08 [2] 5a 0a [2] 1d 1b [2] 53 17 [2] 5f 1d [2] 48 16 [2] 53 58 [2] 6e }

  condition:
    any of them
}
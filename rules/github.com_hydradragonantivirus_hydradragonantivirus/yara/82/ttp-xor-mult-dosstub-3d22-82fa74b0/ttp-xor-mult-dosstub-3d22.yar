rule TTP_XOR_MULT_DOSStub_3d22 {
  strings:
    $key_3d22 = { 69 4a [2] 1d 52 [2] 5a 50 [2] 1d 41 [2] 53 4d [2] 5f 47 [2] 48 4c [2] 53 02 [2] 6e }

  condition:
    any of them
}
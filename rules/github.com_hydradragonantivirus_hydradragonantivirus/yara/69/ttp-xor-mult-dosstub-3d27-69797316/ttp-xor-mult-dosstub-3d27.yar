rule TTP_XOR_MULT_DOSStub_3d27 {
  strings:
    $key_3d27 = { 69 4f [2] 1d 57 [2] 5a 55 [2] 1d 44 [2] 53 48 [2] 5f 42 [2] 48 49 [2] 53 07 [2] 6e }

  condition:
    any of them
}
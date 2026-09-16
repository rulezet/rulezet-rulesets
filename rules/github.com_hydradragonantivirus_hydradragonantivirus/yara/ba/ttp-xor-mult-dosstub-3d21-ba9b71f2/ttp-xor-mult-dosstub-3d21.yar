rule TTP_XOR_MULT_DOSStub_3d21 {
  strings:
    $key_3d21 = { 69 49 [2] 1d 51 [2] 5a 53 [2] 1d 42 [2] 53 4e [2] 5f 44 [2] 48 4f [2] 53 01 [2] 6e }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_1d77 {
  strings:
    $key_1d77 = { 49 1f [2] 3d 07 [2] 7a 05 [2] 3d 14 [2] 73 18 [2] 7f 12 [2] 68 19 [2] 73 57 [2] 4e }

  condition:
    any of them
}
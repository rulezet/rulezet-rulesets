rule TTP_XOR_MULT_DOSStub_1d21 {
  strings:
    $key_1d21 = { 49 49 [2] 3d 51 [2] 7a 53 [2] 3d 42 [2] 73 4e [2] 7f 44 [2] 68 4f [2] 73 01 [2] 4e }

  condition:
    any of them
}
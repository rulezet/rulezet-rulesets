rule TTP_XOR_MULT_DOSStub_1d31 {
  strings:
    $key_1d31 = { 49 59 [2] 3d 41 [2] 7a 43 [2] 3d 52 [2] 73 5e [2] 7f 54 [2] 68 5f [2] 73 11 [2] 4e }

  condition:
    any of them
}
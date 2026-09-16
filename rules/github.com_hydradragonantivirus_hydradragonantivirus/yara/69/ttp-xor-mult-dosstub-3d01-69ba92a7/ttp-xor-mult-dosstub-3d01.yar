rule TTP_XOR_MULT_DOSStub_3d01 {
  strings:
    $key_3d01 = { 69 69 [2] 1d 71 [2] 5a 73 [2] 1d 62 [2] 53 6e [2] 5f 64 [2] 48 6f [2] 53 21 [2] 6e }

  condition:
    any of them
}
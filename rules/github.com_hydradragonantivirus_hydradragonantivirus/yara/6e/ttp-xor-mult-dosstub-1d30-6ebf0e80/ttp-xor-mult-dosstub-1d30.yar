rule TTP_XOR_MULT_DOSStub_1d30 {
  strings:
    $key_1d30 = { 49 58 [2] 3d 40 [2] 7a 42 [2] 3d 53 [2] 73 5f [2] 7f 55 [2] 68 5e [2] 73 10 [2] 4e }

  condition:
    any of them
}
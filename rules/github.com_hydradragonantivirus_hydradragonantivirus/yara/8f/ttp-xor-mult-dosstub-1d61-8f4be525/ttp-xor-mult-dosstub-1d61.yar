rule TTP_XOR_MULT_DOSStub_1d61 {
  strings:
    $key_1d61 = { 49 09 [2] 3d 11 [2] 7a 13 [2] 3d 02 [2] 73 0e [2] 7f 04 [2] 68 0f [2] 73 41 [2] 4e }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_1d67 {
  strings:
    $key_1d67 = { 49 0f [2] 3d 17 [2] 7a 15 [2] 3d 04 [2] 73 08 [2] 7f 02 [2] 68 09 [2] 73 47 [2] 4e }

  condition:
    any of them
}
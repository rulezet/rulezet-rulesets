rule TTP_XOR_MULT_DOSStub_4827 {
  strings:
    $key_4827 = { 1c 4f [2] 68 57 [2] 2f 55 [2] 68 44 [2] 26 48 [2] 2a 42 [2] 3d 49 [2] 26 07 [2] 1b }

  condition:
    any of them
}
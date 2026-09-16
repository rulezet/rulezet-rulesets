rule TTP_XOR_MULT_DOSStub_4837 {
  strings:
    $key_4837 = { 1c 5f [2] 68 47 [2] 2f 45 [2] 68 54 [2] 26 58 [2] 2a 52 [2] 3d 59 [2] 26 17 [2] 1b }

  condition:
    any of them
}
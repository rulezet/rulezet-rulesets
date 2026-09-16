rule TTP_XOR_MULT_DOSStub_4867 {
  strings:
    $key_4867 = { 1c 0f [2] 68 17 [2] 2f 15 [2] 68 04 [2] 26 08 [2] 2a 02 [2] 3d 09 [2] 26 47 [2] 1b }

  condition:
    any of them
}
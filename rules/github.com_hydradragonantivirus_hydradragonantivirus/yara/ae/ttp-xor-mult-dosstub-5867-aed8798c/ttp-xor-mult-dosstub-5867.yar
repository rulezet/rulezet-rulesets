rule TTP_XOR_MULT_DOSStub_5867 {
  strings:
    $key_5867 = { 0c 0f [2] 78 17 [2] 3f 15 [2] 78 04 [2] 36 08 [2] 3a 02 [2] 2d 09 [2] 36 47 [2] 0b }

  condition:
    any of them
}
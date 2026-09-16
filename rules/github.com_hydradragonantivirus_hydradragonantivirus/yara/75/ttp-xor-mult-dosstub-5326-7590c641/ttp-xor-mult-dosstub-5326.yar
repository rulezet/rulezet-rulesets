rule TTP_XOR_MULT_DOSStub_5326 {
  strings:
    $key_5326 = { 07 4e [2] 73 56 [2] 34 54 [2] 73 45 [2] 3d 49 [2] 31 43 [2] 26 48 [2] 3d 06 [2] 00 }

  condition:
    any of them
}
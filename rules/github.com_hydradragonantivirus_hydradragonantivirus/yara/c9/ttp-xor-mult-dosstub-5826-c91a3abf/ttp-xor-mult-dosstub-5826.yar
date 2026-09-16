rule TTP_XOR_MULT_DOSStub_5826 {
  strings:
    $key_5826 = { 0c 4e [2] 78 56 [2] 3f 54 [2] 78 45 [2] 36 49 [2] 3a 43 [2] 2d 48 [2] 36 06 [2] 0b }

  condition:
    any of them
}
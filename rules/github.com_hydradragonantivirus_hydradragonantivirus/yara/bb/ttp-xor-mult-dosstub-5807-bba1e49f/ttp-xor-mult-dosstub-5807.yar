rule TTP_XOR_MULT_DOSStub_5807 {
  strings:
    $key_5807 = { 0c 6f [2] 78 77 [2] 3f 75 [2] 78 64 [2] 36 68 [2] 3a 62 [2] 2d 69 [2] 36 27 [2] 0b }

  condition:
    any of them
}
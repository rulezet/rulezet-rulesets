rule TTP_XOR_MULT_DOSStub_5f07 {
  strings:
    $key_5f07 = { 0b 6f [2] 7f 77 [2] 38 75 [2] 7f 64 [2] 31 68 [2] 3d 62 [2] 2a 69 [2] 31 27 [2] 0c }

  condition:
    any of them
}
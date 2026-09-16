rule TTP_XOR_MULT_DOSStub_5fa8 {
  strings:
    $key_5fa8 = { 0b c0 [2] 7f d8 [2] 38 da [2] 7f cb [2] 31 c7 [2] 3d cd [2] 2a c6 [2] 31 88 [2] 0c }

  condition:
    any of them
}
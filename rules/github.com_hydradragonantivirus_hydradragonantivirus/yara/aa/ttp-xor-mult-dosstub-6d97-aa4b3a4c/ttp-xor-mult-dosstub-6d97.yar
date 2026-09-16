rule TTP_XOR_MULT_DOSStub_6d97 {
  strings:
    $key_6d97 = { 39 ff [2] 4d e7 [2] 0a e5 [2] 4d f4 [2] 03 f8 [2] 0f f2 [2] 18 f9 [2] 03 b7 [2] 3e }

  condition:
    any of them
}
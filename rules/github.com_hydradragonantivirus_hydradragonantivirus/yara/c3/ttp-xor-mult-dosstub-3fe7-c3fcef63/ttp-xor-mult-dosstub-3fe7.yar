rule TTP_XOR_MULT_DOSStub_3fe7 {
  strings:
    $key_3fe7 = { 6b 8f [2] 1f 97 [2] 58 95 [2] 1f 84 [2] 51 88 [2] 5d 82 [2] 4a 89 [2] 51 c7 [2] 6c }

  condition:
    any of them
}
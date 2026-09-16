rule TTP_XOR_MULT_DOSStub_1ba2 {
  strings:
    $key_1ba2 = { 4f ca [2] 3b d2 [2] 7c d0 [2] 3b c1 [2] 75 cd [2] 79 c7 [2] 6e cc [2] 75 82 [2] 48 }

  condition:
    any of them
}
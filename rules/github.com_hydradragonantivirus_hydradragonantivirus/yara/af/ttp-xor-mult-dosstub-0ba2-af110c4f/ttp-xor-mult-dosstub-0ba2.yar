rule TTP_XOR_MULT_DOSStub_0ba2 {
  strings:
    $key_0ba2 = { 5f ca [2] 2b d2 [2] 6c d0 [2] 2b c1 [2] 65 cd [2] 69 c7 [2] 7e cc [2] 65 82 [2] 58 }

  condition:
    any of them
}
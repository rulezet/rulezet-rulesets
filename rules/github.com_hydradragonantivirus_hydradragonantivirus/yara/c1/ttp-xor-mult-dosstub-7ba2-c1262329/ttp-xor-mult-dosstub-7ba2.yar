rule TTP_XOR_MULT_DOSStub_7ba2 {
  strings:
    $key_7ba2 = { 2f ca [2] 5b d2 [2] 1c d0 [2] 5b c1 [2] 15 cd [2] 19 c7 [2] 0e cc [2] 15 82 [2] 28 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_2ba2 {
  strings:
    $key_2ba2 = { 7f ca [2] 0b d2 [2] 4c d0 [2] 0b c1 [2] 45 cd [2] 49 c7 [2] 5e cc [2] 45 82 [2] 78 }

  condition:
    any of them
}
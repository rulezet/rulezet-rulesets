rule TTP_XOR_MULT_DOSStub_6ba2 {
  strings:
    $key_6ba2 = { 3f ca [2] 4b d2 [2] 0c d0 [2] 4b c1 [2] 05 cd [2] 09 c7 [2] 1e cc [2] 05 82 [2] 38 }

  condition:
    any of them
}
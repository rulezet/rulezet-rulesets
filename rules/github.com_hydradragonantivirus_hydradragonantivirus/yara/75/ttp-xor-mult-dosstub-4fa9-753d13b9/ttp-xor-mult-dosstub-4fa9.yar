rule TTP_XOR_MULT_DOSStub_4fa9 {
  strings:
    $key_4fa9 = { 1b c1 [2] 6f d9 [2] 28 db [2] 6f ca [2] 21 c6 [2] 2d cc [2] 3a c7 [2] 21 89 [2] 1c }

  condition:
    any of them
}
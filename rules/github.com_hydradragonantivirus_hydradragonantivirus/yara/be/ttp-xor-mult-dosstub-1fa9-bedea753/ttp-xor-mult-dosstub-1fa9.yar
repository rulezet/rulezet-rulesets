rule TTP_XOR_MULT_DOSStub_1fa9 {
  strings:
    $key_1fa9 = { 4b c1 [2] 3f d9 [2] 78 db [2] 3f ca [2] 71 c6 [2] 7d cc [2] 6a c7 [2] 71 89 [2] 4c }

  condition:
    any of them
}
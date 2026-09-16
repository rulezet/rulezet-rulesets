rule TTP_XOR_MULT_DOSStub_3fa9 {
  strings:
    $key_3fa9 = { 6b c1 [2] 1f d9 [2] 58 db [2] 1f ca [2] 51 c6 [2] 5d cc [2] 4a c7 [2] 51 89 [2] 6c }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_238a {
  strings:
    $key_238a = { 77 e2 [2] 03 fa [2] 44 f8 [2] 03 e9 [2] 4d e5 [2] 41 ef [2] 56 e4 [2] 4d aa [2] 70 }

  condition:
    any of them
}
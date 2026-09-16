rule TTP_XOR_MULT_DOSStub_cd87 {
  strings:
    $key_cd87 = { 99 ef [2] ed f7 [2] aa f5 [2] ed e4 [2] a3 e8 [2] af e2 [2] b8 e9 [2] a3 a7 [2] 9e }

  condition:
    any of them
}
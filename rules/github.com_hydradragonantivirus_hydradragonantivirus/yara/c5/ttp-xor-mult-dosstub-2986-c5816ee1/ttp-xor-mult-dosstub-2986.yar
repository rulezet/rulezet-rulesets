rule TTP_XOR_MULT_DOSStub_2986 {
  strings:
    $key_2986 = { 7d ee [2] 09 f6 [2] 4e f4 [2] 09 e5 [2] 47 e9 [2] 4b e3 [2] 5c e8 [2] 47 a6 [2] 7a }

  condition:
    any of them
}
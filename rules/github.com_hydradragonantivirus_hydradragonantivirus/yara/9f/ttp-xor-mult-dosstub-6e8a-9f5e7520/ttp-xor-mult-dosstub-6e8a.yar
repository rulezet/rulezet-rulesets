rule TTP_XOR_MULT_DOSStub_6e8a {
  strings:
    $key_6e8a = { 3a e2 [2] 4e fa [2] 09 f8 [2] 4e e9 [2] 00 e5 [2] 0c ef [2] 1b e4 [2] 00 aa [2] 3d }

  condition:
    any of them
}
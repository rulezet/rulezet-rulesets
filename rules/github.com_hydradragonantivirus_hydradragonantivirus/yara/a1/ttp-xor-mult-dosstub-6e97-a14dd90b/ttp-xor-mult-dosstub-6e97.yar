rule TTP_XOR_MULT_DOSStub_6e97 {
  strings:
    $key_6e97 = { 3a ff [2] 4e e7 [2] 09 e5 [2] 4e f4 [2] 00 f8 [2] 0c f2 [2] 1b f9 [2] 00 b7 [2] 3d }

  condition:
    any of them
}
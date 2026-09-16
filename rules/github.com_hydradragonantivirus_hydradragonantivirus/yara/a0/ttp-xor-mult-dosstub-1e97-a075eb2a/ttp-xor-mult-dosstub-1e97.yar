rule TTP_XOR_MULT_DOSStub_1e97 {
  strings:
    $key_1e97 = { 4a ff [2] 3e e7 [2] 79 e5 [2] 3e f4 [2] 70 f8 [2] 7c f2 [2] 6b f9 [2] 70 b7 [2] 4d }

  condition:
    any of them
}
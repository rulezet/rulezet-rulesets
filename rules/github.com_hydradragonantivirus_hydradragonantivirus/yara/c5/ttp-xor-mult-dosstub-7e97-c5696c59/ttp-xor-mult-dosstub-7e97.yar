rule TTP_XOR_MULT_DOSStub_7e97 {
  strings:
    $key_7e97 = { 2a ff [2] 5e e7 [2] 19 e5 [2] 5e f4 [2] 10 f8 [2] 1c f2 [2] 0b f9 [2] 10 b7 [2] 2d }

  condition:
    any of them
}
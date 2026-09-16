rule TTP_XOR_MULT_DOSStub_3e97 {
  strings:
    $key_3e97 = { 6a ff [2] 1e e7 [2] 59 e5 [2] 1e f4 [2] 50 f8 [2] 5c f2 [2] 4b f9 [2] 50 b7 [2] 6d }

  condition:
    any of them
}
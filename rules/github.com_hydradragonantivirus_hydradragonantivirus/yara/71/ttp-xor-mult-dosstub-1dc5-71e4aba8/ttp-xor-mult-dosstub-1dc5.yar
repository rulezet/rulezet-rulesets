rule TTP_XOR_MULT_DOSStub_1dc5 {
  strings:
    $key_1dc5 = { 49 ad [2] 3d b5 [2] 7a b7 [2] 3d a6 [2] 73 aa [2] 7f a0 [2] 68 ab [2] 73 e5 [2] 4e }

  condition:
    any of them
}
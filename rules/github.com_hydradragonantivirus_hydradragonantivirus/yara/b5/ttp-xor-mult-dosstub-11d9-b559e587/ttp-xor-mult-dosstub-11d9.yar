rule TTP_XOR_MULT_DOSStub_11d9 {
  strings:
    $key_11d9 = { 45 b1 [2] 31 a9 [2] 76 ab [2] 31 ba [2] 7f b6 [2] 73 bc [2] 64 b7 [2] 7f f9 [2] 42 }

  condition:
    any of them
}
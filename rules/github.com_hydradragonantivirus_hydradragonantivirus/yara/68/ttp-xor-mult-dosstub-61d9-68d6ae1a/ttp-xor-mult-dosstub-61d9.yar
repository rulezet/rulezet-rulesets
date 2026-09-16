rule TTP_XOR_MULT_DOSStub_61d9 {
  strings:
    $key_61d9 = { 35 b1 [2] 41 a9 [2] 06 ab [2] 41 ba [2] 0f b6 [2] 03 bc [2] 14 b7 [2] 0f f9 [2] 32 }

  condition:
    any of them
}
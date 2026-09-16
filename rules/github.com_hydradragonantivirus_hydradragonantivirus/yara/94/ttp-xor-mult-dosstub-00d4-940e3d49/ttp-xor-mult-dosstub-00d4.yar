rule TTP_XOR_MULT_DOSStub_00d4 {
  strings:
    $key_00d4 = { 54 bc [2] 20 a4 [2] 67 a6 [2] 20 b7 [2] 6e bb [2] 62 b1 [2] 75 ba [2] 6e f4 [2] 53 }

  condition:
    any of them
}
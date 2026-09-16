rule TTP_XOR_MULT_DOSStub_4bb2 {
  strings:
    $key_4bb2 = { 1f da [2] 6b c2 [2] 2c c0 [2] 6b d1 [2] 25 dd [2] 29 d7 [2] 3e dc [2] 25 92 [2] 18 }

  condition:
    any of them
}
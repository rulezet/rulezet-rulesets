rule TTP_XOR_MULT_DOSStub_0bb2 {
  strings:
    $key_0bb2 = { 5f da [2] 2b c2 [2] 6c c0 [2] 2b d1 [2] 65 dd [2] 69 d7 [2] 7e dc [2] 65 92 [2] 58 }

  condition:
    any of them
}
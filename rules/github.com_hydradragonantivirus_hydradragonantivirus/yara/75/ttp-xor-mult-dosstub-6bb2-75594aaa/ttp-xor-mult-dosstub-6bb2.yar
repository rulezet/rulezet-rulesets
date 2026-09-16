rule TTP_XOR_MULT_DOSStub_6bb2 {
  strings:
    $key_6bb2 = { 3f da [2] 4b c2 [2] 0c c0 [2] 4b d1 [2] 05 dd [2] 09 d7 [2] 1e dc [2] 05 92 [2] 38 }

  condition:
    any of them
}
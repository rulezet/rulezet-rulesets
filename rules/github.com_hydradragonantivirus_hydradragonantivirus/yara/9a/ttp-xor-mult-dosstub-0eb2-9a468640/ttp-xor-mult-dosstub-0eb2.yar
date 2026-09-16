rule TTP_XOR_MULT_DOSStub_0eb2 {
  strings:
    $key_0eb2 = { 5a da [2] 2e c2 [2] 69 c0 [2] 2e d1 [2] 60 dd [2] 6c d7 [2] 7b dc [2] 60 92 [2] 5d }

  condition:
    any of them
}
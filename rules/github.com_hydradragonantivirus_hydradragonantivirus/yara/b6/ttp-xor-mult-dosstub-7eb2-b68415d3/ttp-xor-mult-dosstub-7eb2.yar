rule TTP_XOR_MULT_DOSStub_7eb2 {
  strings:
    $key_7eb2 = { 2a da [2] 5e c2 [2] 19 c0 [2] 5e d1 [2] 10 dd [2] 1c d7 [2] 0b dc [2] 10 92 [2] 2d }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_19b3 {
  strings:
    $key_19b3 = { 4d db [2] 39 c3 [2] 7e c1 [2] 39 d0 [2] 77 dc [2] 7b d6 [2] 6c dd [2] 77 93 [2] 4a }

  condition:
    any of them
}
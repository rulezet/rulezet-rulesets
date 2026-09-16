rule TTP_XOR_MULT_DOSStub_7cb8 {
  strings:
    $key_7cb8 = { 28 d0 [2] 5c c8 [2] 1b ca [2] 5c db [2] 12 d7 [2] 1e dd [2] 09 d6 [2] 12 98 [2] 2f }

  condition:
    any of them
}
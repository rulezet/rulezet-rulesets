rule TTP_XOR_MULT_DOSStub_3cb8 {
  strings:
    $key_3cb8 = { 68 d0 [2] 1c c8 [2] 5b ca [2] 1c db [2] 52 d7 [2] 5e dd [2] 49 d6 [2] 52 98 [2] 6f }

  condition:
    any of them
}
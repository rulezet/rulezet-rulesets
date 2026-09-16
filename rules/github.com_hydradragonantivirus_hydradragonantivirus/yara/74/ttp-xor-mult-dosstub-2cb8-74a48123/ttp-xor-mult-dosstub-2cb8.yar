rule TTP_XOR_MULT_DOSStub_2cb8 {
  strings:
    $key_2cb8 = { 78 d0 [2] 0c c8 [2] 4b ca [2] 0c db [2] 42 d7 [2] 4e dd [2] 59 d6 [2] 42 98 [2] 7f }

  condition:
    any of them
}
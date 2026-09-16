rule TTP_XOR_MULT_DOSStub_f9a8 {
  strings:
    $key_f9a8 = { ad c0 [2] d9 d8 [2] 9e da [2] d9 cb [2] 97 c7 [2] 9b cd [2] 8c c6 [2] 97 88 [2] aa }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_e9a8 {
  strings:
    $key_e9a8 = { bd c0 [2] c9 d8 [2] 8e da [2] c9 cb [2] 87 c7 [2] 8b cd [2] 9c c6 [2] 87 88 [2] ba }

  condition:
    any of them
}
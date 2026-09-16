rule TTP_XOR_MULT_DOSStub_08a5 {
  strings:
    $key_08a5 = { 5c cd [2] 28 d5 [2] 6f d7 [2] 28 c6 [2] 66 ca [2] 6a c0 [2] 7d cb [2] 66 85 [2] 5b }

  condition:
    any of them
}
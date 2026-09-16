rule TTP_XOR_MULT_DOSStub_38a5 {
  strings:
    $key_38a5 = { 6c cd [2] 18 d5 [2] 5f d7 [2] 18 c6 [2] 56 ca [2] 5a c0 [2] 4d cb [2] 56 85 [2] 6b }

  condition:
    any of them
}
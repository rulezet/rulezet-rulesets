rule TTP_XOR_MULT_DOSStub_48a5 {
  strings:
    $key_48a5 = { 1c cd [2] 68 d5 [2] 2f d7 [2] 68 c6 [2] 26 ca [2] 2a c0 [2] 3d cb [2] 26 85 [2] 1b }

  condition:
    any of them
}
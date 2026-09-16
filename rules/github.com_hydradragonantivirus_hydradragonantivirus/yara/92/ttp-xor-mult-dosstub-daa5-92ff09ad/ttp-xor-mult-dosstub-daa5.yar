rule TTP_XOR_MULT_DOSStub_daa5 {
  strings:
    $key_daa5 = { 8e cd [2] fa d5 [2] bd d7 [2] fa c6 [2] b4 ca [2] b8 c0 [2] af cb [2] b4 85 [2] 89 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_aea5 {
  strings:
    $key_aea5 = { fa cd [2] 8e d5 [2] c9 d7 [2] 8e c6 [2] c0 ca [2] cc c0 [2] db cb [2] c0 85 [2] fd }

  condition:
    any of them
}
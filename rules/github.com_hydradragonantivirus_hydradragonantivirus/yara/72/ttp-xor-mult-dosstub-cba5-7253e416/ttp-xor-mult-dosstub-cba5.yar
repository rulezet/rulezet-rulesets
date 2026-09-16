rule TTP_XOR_MULT_DOSStub_cba5 {
  strings:
    $key_cba5 = { 9f cd [2] eb d5 [2] ac d7 [2] eb c6 [2] a5 ca [2] a9 c0 [2] be cb [2] a5 85 [2] 98 }

  condition:
    any of them
}
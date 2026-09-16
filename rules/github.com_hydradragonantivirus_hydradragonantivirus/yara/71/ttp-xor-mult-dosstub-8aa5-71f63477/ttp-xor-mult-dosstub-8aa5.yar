rule TTP_XOR_MULT_DOSStub_8aa5 {
  strings:
    $key_8aa5 = { de cd [2] aa d5 [2] ed d7 [2] aa c6 [2] e4 ca [2] e8 c0 [2] ff cb [2] e4 85 [2] d9 }

  condition:
    any of them
}
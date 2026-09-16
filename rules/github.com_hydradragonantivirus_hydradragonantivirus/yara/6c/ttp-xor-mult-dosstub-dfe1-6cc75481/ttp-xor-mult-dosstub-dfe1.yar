rule TTP_XOR_MULT_DOSStub_dfe1 {
  strings:
    $key_dfe1 = { 8b 89 [2] ff 91 [2] b8 93 [2] ff 82 [2] b1 8e [2] bd 84 [2] aa 8f [2] b1 c1 [2] 8c }

  condition:
    any of them
}
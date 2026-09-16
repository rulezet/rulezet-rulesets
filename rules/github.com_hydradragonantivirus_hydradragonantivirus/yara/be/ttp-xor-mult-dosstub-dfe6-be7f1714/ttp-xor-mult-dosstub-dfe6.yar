rule TTP_XOR_MULT_DOSStub_dfe6 {
  strings:
    $key_dfe6 = { 8b 8e [2] ff 96 [2] b8 94 [2] ff 85 [2] b1 89 [2] bd 83 [2] aa 88 [2] b1 c6 [2] 8c }

  condition:
    any of them
}
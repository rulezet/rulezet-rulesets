rule TTP_XOR_MULT_DOSStub_dfe0 {
  strings:
    $key_dfe0 = { 8b 88 [2] ff 90 [2] b8 92 [2] ff 83 [2] b1 8f [2] bd 85 [2] aa 8e [2] b1 c0 [2] 8c }

  condition:
    any of them
}
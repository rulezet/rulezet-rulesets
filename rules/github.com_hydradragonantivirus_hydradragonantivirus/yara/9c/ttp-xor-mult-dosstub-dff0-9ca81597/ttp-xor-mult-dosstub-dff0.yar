rule TTP_XOR_MULT_DOSStub_dff0 {
  strings:
    $key_dff0 = { 8b 98 [2] ff 80 [2] b8 82 [2] ff 93 [2] b1 9f [2] bd 95 [2] aa 9e [2] b1 d0 [2] 8c }

  condition:
    any of them
}
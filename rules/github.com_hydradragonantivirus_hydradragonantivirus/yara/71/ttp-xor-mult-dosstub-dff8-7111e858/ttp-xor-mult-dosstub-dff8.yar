rule TTP_XOR_MULT_DOSStub_dff8 {
  strings:
    $key_dff8 = { 8b 90 [2] ff 88 [2] b8 8a [2] ff 9b [2] b1 97 [2] bd 9d [2] aa 96 [2] b1 d8 [2] 8c }

  condition:
    any of them
}
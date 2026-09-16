rule TTP_XOR_MULT_DOSStub_dff9 {
  strings:
    $key_dff9 = { 8b 91 [2] ff 89 [2] b8 8b [2] ff 9a [2] b1 96 [2] bd 9c [2] aa 97 [2] b1 d9 [2] 8c }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_dff2 {
  strings:
    $key_dff2 = { 8b 9a [2] ff 82 [2] b8 80 [2] ff 91 [2] b1 9d [2] bd 97 [2] aa 9c [2] b1 d2 [2] 8c }

  condition:
    any of them
}
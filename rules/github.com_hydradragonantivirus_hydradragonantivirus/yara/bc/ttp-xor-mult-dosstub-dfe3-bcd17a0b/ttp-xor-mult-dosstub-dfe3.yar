rule TTP_XOR_MULT_DOSStub_dfe3 {
  strings:
    $key_dfe3 = { 8b 8b [2] ff 93 [2] b8 91 [2] ff 80 [2] b1 8c [2] bd 86 [2] aa 8d [2] b1 c3 [2] 8c }

  condition:
    any of them
}
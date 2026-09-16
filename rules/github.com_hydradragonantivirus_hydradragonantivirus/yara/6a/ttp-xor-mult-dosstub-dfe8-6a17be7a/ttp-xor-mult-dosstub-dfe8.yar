rule TTP_XOR_MULT_DOSStub_dfe8 {
  strings:
    $key_dfe8 = { 8b 80 [2] ff 98 [2] b8 9a [2] ff 8b [2] b1 87 [2] bd 8d [2] aa 86 [2] b1 c8 [2] 8c }

  condition:
    any of them
}
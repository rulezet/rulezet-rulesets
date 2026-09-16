rule TTP_XOR_MULT_DOSStub_dffc {
  strings:
    $key_dffc = { 8b 94 [2] ff 8c [2] b8 8e [2] ff 9f [2] b1 93 [2] bd 99 [2] aa 92 [2] b1 dc [2] 8c }

  condition:
    any of them
}
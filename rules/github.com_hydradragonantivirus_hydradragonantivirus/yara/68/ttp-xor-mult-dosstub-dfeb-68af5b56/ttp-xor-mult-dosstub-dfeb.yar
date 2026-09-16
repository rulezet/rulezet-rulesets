rule TTP_XOR_MULT_DOSStub_dfeb {
  strings:
    $key_dfeb = { 8b 83 [2] ff 9b [2] b8 99 [2] ff 88 [2] b1 84 [2] bd 8e [2] aa 85 [2] b1 cb [2] 8c }

  condition:
    any of them
}
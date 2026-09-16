rule TTP_XOR_MULT_DOSStub_dffb {
  strings:
    $key_dffb = { 8b 93 [2] ff 8b [2] b8 89 [2] ff 98 [2] b1 94 [2] bd 9e [2] aa 95 [2] b1 db [2] 8c }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_dfee {
  strings:
    $key_dfee = { 8b 86 [2] ff 9e [2] b8 9c [2] ff 8d [2] b1 81 [2] bd 8b [2] aa 80 [2] b1 ce [2] 8c }

  condition:
    any of them
}
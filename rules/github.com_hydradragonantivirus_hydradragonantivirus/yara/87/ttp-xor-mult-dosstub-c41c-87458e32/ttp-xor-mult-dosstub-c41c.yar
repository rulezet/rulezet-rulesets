rule TTP_XOR_MULT_DOSStub_c41c {
  strings:
    $key_c41c = { 90 74 [2] e4 6c [2] a3 6e [2] e4 7f [2] aa 73 [2] a6 79 [2] b1 72 [2] aa 3c [2] 97 }

  condition:
    any of them
}
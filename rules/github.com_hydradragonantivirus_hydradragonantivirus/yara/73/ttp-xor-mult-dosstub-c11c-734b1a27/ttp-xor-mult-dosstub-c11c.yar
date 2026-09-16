rule TTP_XOR_MULT_DOSStub_c11c {
  strings:
    $key_c11c = { 95 74 [2] e1 6c [2] a6 6e [2] e1 7f [2] af 73 [2] a3 79 [2] b4 72 [2] af 3c [2] 92 }

  condition:
    any of them
}
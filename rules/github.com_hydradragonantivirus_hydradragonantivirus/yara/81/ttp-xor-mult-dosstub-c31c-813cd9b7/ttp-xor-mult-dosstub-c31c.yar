rule TTP_XOR_MULT_DOSStub_c31c {
  strings:
    $key_c31c = { 97 74 [2] e3 6c [2] a4 6e [2] e3 7f [2] ad 73 [2] a1 79 [2] b6 72 [2] ad 3c [2] 90 }

  condition:
    any of them
}
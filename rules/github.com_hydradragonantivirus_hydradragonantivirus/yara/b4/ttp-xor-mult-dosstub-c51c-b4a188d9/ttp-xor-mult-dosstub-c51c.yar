rule TTP_XOR_MULT_DOSStub_c51c {
  strings:
    $key_c51c = { 91 74 [2] e5 6c [2] a2 6e [2] e5 7f [2] ab 73 [2] a7 79 [2] b0 72 [2] ab 3c [2] 96 }

  condition:
    any of them
}
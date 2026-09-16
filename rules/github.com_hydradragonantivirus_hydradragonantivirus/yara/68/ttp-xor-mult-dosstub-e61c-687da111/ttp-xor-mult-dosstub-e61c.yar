rule TTP_XOR_MULT_DOSStub_e61c {
  strings:
    $key_e61c = { b2 74 [2] c6 6c [2] 81 6e [2] c6 7f [2] 88 73 [2] 84 79 [2] 93 72 [2] 88 3c [2] b5 }

  condition:
    any of them
}
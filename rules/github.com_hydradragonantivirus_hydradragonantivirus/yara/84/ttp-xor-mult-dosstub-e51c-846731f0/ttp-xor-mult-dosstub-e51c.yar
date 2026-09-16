rule TTP_XOR_MULT_DOSStub_e51c {
  strings:
    $key_e51c = { b1 74 [2] c5 6c [2] 82 6e [2] c5 7f [2] 8b 73 [2] 87 79 [2] 90 72 [2] 8b 3c [2] b6 }

  condition:
    any of them
}
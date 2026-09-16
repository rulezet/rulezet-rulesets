rule TTP_XOR_MULT_DOSStub_e54c {
  strings:
    $key_e54c = { b1 24 [2] c5 3c [2] 82 3e [2] c5 2f [2] 8b 23 [2] 87 29 [2] 90 22 [2] 8b 6c [2] b6 }

  condition:
    any of them
}
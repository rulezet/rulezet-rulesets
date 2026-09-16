rule TTP_XOR_MULT_DOSStub_e53c {
  strings:
    $key_e53c = { b1 54 [2] c5 4c [2] 82 4e [2] c5 5f [2] 8b 53 [2] 87 59 [2] 90 52 [2] 8b 1c [2] b6 }

  condition:
    any of them
}
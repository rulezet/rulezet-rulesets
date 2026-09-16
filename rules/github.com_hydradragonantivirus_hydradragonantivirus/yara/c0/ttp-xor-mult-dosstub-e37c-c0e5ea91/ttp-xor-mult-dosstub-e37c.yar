rule TTP_XOR_MULT_DOSStub_e37c {
  strings:
    $key_e37c = { b7 14 [2] c3 0c [2] 84 0e [2] c3 1f [2] 8d 13 [2] 81 19 [2] 96 12 [2] 8d 5c [2] b0 }

  condition:
    any of them
}
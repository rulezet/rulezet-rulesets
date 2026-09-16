rule TTP_XOR_MULT_DOSStub_e63c {
  strings:
    $key_e63c = { b2 54 [2] c6 4c [2] 81 4e [2] c6 5f [2] 88 53 [2] 84 59 [2] 93 52 [2] 88 1c [2] b5 }

  condition:
    any of them
}
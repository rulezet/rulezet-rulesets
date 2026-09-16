rule TTP_XOR_MULT_DOSStub_b73c {
  strings:
    $key_b73c = { e3 54 [2] 97 4c [2] d0 4e [2] 97 5f [2] d9 53 [2] d5 59 [2] c2 52 [2] d9 1c [2] e4 }

  condition:
    any of them
}
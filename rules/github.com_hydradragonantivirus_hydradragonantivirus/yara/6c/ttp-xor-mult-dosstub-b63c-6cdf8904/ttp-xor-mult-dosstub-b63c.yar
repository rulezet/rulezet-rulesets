rule TTP_XOR_MULT_DOSStub_b63c {
  strings:
    $key_b63c = { e2 54 [2] 96 4c [2] d1 4e [2] 96 5f [2] d8 53 [2] d4 59 [2] c3 52 [2] d8 1c [2] e5 }

  condition:
    any of them
}
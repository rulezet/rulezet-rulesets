rule TTP_XOR_MULT_DOSStub_463c {
  strings:
    $key_463c = { 12 54 [2] 66 4c [2] 21 4e [2] 66 5f [2] 28 53 [2] 24 59 [2] 33 52 [2] 28 1c [2] 15 }

  condition:
    any of them
}
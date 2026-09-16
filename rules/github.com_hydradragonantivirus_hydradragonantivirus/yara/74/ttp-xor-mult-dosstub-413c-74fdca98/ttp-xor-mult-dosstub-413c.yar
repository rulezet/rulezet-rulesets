rule TTP_XOR_MULT_DOSStub_413c {
  strings:
    $key_413c = { 15 54 [2] 61 4c [2] 26 4e [2] 61 5f [2] 2f 53 [2] 23 59 [2] 34 52 [2] 2f 1c [2] 12 }

  condition:
    any of them
}
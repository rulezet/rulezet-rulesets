rule TTP_XOR_MULT_DOSStub_003c {
  strings:
    $key_003c = { 54 54 [2] 20 4c [2] 67 4e [2] 20 5f [2] 6e 53 [2] 62 59 [2] 75 52 [2] 6e 1c [2] 53 }

  condition:
    any of them
}
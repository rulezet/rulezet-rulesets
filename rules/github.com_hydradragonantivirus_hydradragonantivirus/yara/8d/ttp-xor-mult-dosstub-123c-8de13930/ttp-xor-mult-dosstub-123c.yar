rule TTP_XOR_MULT_DOSStub_123c {
  strings:
    $key_123c = { 46 54 [2] 32 4c [2] 75 4e [2] 32 5f [2] 7c 53 [2] 70 59 [2] 67 52 [2] 7c 1c [2] 41 }

  condition:
    any of them
}
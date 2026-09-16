rule TTP_XOR_MULT_DOSStub_443c {
  strings:
    $key_443c = { 10 54 [2] 64 4c [2] 23 4e [2] 64 5f [2] 2a 53 [2] 26 59 [2] 31 52 [2] 2a 1c [2] 17 }

  condition:
    any of them
}
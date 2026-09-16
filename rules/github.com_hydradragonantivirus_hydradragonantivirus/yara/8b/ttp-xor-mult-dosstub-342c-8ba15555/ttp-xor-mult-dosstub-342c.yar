rule TTP_XOR_MULT_DOSStub_342c {
  strings:
    $key_342c = { 60 44 [2] 14 5c [2] 53 5e [2] 14 4f [2] 5a 43 [2] 56 49 [2] 41 42 [2] 5a 0c [2] 67 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_b74c {
  strings:
    $key_b74c = { e3 24 [2] 97 3c [2] d0 3e [2] 97 2f [2] d9 23 [2] d5 29 [2] c2 22 [2] d9 6c [2] e4 }

  condition:
    any of them
}
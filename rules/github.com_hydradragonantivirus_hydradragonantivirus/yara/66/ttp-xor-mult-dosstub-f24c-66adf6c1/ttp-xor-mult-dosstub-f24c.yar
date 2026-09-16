rule TTP_XOR_MULT_DOSStub_f24c {
  strings:
    $key_f24c = { a6 24 [2] d2 3c [2] 95 3e [2] d2 2f [2] 9c 23 [2] 90 29 [2] 87 22 [2] 9c 6c [2] a1 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_f22b {
  strings:
    $key_f22b = { a6 43 [2] d2 5b [2] 95 59 [2] d2 48 [2] 9c 44 [2] 90 4e [2] 87 45 [2] 9c 0b [2] a1 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_f67c {
  strings:
    $key_f67c = { a2 14 [2] d6 0c [2] 91 0e [2] d6 1f [2] 98 13 [2] 94 19 [2] 83 12 [2] 98 5c [2] a5 }

  condition:
    any of them
}
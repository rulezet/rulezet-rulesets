rule TTP_XOR_MULT_DOSStub_f62b {
  strings:
    $key_f62b = { a2 43 [2] d6 5b [2] 91 59 [2] d6 48 [2] 98 44 [2] 94 4e [2] 83 45 [2] 98 0b [2] a5 }

  condition:
    any of them
}
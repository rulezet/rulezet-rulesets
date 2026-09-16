rule TTP_XOR_MULT_DOSStub_f62d {
  strings:
    $key_f62d = { a2 45 [2] d6 5d [2] 91 5f [2] d6 4e [2] 98 42 [2] 94 48 [2] 83 43 [2] 98 0d [2] a5 }

  condition:
    any of them
}
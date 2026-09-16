rule TTP_XOR_MULT_DOSStub_f62c {
  strings:
    $key_f62c = { a2 44 [2] d6 5c [2] 91 5e [2] d6 4f [2] 98 43 [2] 94 49 [2] 83 42 [2] 98 0c [2] a5 }

  condition:
    any of them
}
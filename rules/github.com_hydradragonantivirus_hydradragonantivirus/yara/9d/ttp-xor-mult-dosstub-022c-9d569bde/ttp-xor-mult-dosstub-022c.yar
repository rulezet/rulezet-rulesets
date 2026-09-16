rule TTP_XOR_MULT_DOSStub_022c {
  strings:
    $key_022c = { 56 44 [2] 22 5c [2] 65 5e [2] 22 4f [2] 6c 43 [2] 60 49 [2] 77 42 [2] 6c 0c [2] 51 }

  condition:
    any of them
}
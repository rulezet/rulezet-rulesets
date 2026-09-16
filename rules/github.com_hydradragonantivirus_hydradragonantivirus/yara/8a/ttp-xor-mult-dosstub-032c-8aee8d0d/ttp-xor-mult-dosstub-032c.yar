rule TTP_XOR_MULT_DOSStub_032c {
  strings:
    $key_032c = { 57 44 [2] 23 5c [2] 64 5e [2] 23 4f [2] 6d 43 [2] 61 49 [2] 76 42 [2] 6d 0c [2] 50 }

  condition:
    any of them
}
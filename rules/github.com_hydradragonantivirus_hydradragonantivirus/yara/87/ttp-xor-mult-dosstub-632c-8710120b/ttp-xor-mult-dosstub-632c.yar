rule TTP_XOR_MULT_DOSStub_632c {
  strings:
    $key_632c = { 37 44 [2] 43 5c [2] 04 5e [2] 43 4f [2] 0d 43 [2] 01 49 [2] 16 42 [2] 0d 0c [2] 30 }

  condition:
    any of them
}
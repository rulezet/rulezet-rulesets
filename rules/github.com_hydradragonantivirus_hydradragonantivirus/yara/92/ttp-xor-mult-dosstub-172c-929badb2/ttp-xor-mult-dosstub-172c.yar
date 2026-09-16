rule TTP_XOR_MULT_DOSStub_172c {
  strings:
    $key_172c = { 43 44 [2] 37 5c [2] 70 5e [2] 37 4f [2] 79 43 [2] 75 49 [2] 62 42 [2] 79 0c [2] 44 }

  condition:
    any of them
}
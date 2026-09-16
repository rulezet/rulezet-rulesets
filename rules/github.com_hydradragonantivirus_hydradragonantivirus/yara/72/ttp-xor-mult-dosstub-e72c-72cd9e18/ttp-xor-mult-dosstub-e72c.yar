rule TTP_XOR_MULT_DOSStub_e72c {
  strings:
    $key_e72c = { b3 44 [2] c7 5c [2] 80 5e [2] c7 4f [2] 89 43 [2] 85 49 [2] 92 42 [2] 89 0c [2] b4 }

  condition:
    any of them
}
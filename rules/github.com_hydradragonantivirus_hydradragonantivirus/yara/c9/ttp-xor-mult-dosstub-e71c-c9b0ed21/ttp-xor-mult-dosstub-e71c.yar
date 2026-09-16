rule TTP_XOR_MULT_DOSStub_e71c {
  strings:
    $key_e71c = { b3 74 [2] c7 6c [2] 80 6e [2] c7 7f [2] 89 73 [2] 85 79 [2] 92 72 [2] 89 3c [2] b4 }

  condition:
    any of them
}
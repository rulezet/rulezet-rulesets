rule TTP_XOR_MULT_DOSStub_114c {
  strings:
    $key_114c = { 45 24 [2] 31 3c [2] 76 3e [2] 31 2f [2] 7f 23 [2] 73 29 [2] 64 22 [2] 7f 6c [2] 42 }

  condition:
    any of them
}
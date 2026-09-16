rule TTP_XOR_MULT_DOSStub_f41b {
  strings:
    $key_f41b = { a0 73 [2] d4 6b [2] 93 69 [2] d4 78 [2] 9a 74 [2] 96 7e [2] 81 75 [2] 9a 3b [2] a7 }

  condition:
    any of them
}
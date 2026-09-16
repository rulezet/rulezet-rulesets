rule TTP_XOR_MULT_DOSStub_72e1 {
  strings:
    $key_72e1 = { 26 89 [2] 52 91 [2] 15 93 [2] 52 82 [2] 1c 8e [2] 10 84 [2] 07 8f [2] 1c c1 [2] 21 }

  condition:
    any of them
}
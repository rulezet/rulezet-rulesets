rule TTP_XOR_MULT_DOSStub_5fe1 {
  strings:
    $key_5fe1 = { 0b 89 [2] 7f 91 [2] 38 93 [2] 7f 82 [2] 31 8e [2] 3d 84 [2] 2a 8f [2] 31 c1 [2] 0c }

  condition:
    any of them
}
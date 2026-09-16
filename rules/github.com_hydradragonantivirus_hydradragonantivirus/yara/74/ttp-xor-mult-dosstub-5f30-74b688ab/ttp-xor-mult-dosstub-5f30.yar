rule TTP_XOR_MULT_DOSStub_5f30 {
  strings:
    $key_5f30 = { 0b 58 [2] 7f 40 [2] 38 42 [2] 7f 53 [2] 31 5f [2] 3d 55 [2] 2a 5e [2] 31 10 [2] 0c }

  condition:
    any of them
}
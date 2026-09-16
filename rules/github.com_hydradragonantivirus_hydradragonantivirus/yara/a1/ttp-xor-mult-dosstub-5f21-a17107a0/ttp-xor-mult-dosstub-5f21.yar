rule TTP_XOR_MULT_DOSStub_5f21 {
  strings:
    $key_5f21 = { 0b 49 [2] 7f 51 [2] 38 53 [2] 7f 42 [2] 31 4e [2] 3d 44 [2] 2a 4f [2] 31 01 [2] 0c }

  condition:
    any of them
}
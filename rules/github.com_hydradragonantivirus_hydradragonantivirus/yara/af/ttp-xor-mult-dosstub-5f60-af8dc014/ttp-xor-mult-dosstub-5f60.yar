rule TTP_XOR_MULT_DOSStub_5f60 {
  strings:
    $key_5f60 = { 0b 08 [2] 7f 10 [2] 38 12 [2] 7f 03 [2] 31 0f [2] 3d 05 [2] 2a 0e [2] 31 40 [2] 0c }

  condition:
    any of them
}
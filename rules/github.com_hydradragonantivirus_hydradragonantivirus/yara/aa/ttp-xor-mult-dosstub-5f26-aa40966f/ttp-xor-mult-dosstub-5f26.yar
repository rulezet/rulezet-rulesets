rule TTP_XOR_MULT_DOSStub_5f26 {
  strings:
    $key_5f26 = { 0b 4e [2] 7f 56 [2] 38 54 [2] 7f 45 [2] 31 49 [2] 3d 43 [2] 2a 48 [2] 31 06 [2] 0c }

  condition:
    any of them
}
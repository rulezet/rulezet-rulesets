rule TTP_XOR_MULT_DOSStub_5ae1 {
  strings:
    $key_5ae1 = { 0e 89 [2] 7a 91 [2] 3d 93 [2] 7a 82 [2] 34 8e [2] 38 84 [2] 2f 8f [2] 34 c1 [2] 09 }

  condition:
    any of them
}
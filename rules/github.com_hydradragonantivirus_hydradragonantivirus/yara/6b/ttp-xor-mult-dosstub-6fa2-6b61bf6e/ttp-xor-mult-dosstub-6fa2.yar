rule TTP_XOR_MULT_DOSStub_6fa2 {
  strings:
    $key_6fa2 = { 3b ca [2] 4f d2 [2] 08 d0 [2] 4f c1 [2] 01 cd [2] 0d c7 [2] 1a cc [2] 01 82 [2] 3c }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_4fa2 {
  strings:
    $key_4fa2 = { 1b ca [2] 6f d2 [2] 28 d0 [2] 6f c1 [2] 21 cd [2] 2d c7 [2] 3a cc [2] 21 82 [2] 1c }

  condition:
    any of them
}
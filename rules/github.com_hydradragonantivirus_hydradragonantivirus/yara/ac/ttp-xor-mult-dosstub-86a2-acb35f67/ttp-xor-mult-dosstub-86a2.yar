rule TTP_XOR_MULT_DOSStub_86a2 {
  strings:
    $key_86a2 = { d2 ca [2] a6 d2 [2] e1 d0 [2] a6 c1 [2] e8 cd [2] e4 c7 [2] f3 cc [2] e8 82 [2] d5 }

  condition:
    any of them
}
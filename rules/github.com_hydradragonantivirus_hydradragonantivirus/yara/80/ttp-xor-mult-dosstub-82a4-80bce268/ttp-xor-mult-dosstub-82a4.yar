rule TTP_XOR_MULT_DOSStub_82a4 {
  strings:
    $key_82a4 = { d6 cc [2] a2 d4 [2] e5 d6 [2] a2 c7 [2] ec cb [2] e0 c1 [2] f7 ca [2] ec 84 [2] d1 }

  condition:
    any of them
}
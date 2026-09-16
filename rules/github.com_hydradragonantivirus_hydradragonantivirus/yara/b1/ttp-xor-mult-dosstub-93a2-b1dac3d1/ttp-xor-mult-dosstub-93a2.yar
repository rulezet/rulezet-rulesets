rule TTP_XOR_MULT_DOSStub_93a2 {
  strings:
    $key_93a2 = { c7 ca [2] b3 d2 [2] f4 d0 [2] b3 c1 [2] fd cd [2] f1 c7 [2] e6 cc [2] fd 82 [2] c0 }

  condition:
    any of them
}
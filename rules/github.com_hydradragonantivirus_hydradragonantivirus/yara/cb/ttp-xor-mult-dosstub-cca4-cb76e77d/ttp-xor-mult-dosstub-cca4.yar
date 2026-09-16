rule TTP_XOR_MULT_DOSStub_cca4 {
  strings:
    $key_cca4 = { 98 cc [2] ec d4 [2] ab d6 [2] ec c7 [2] a2 cb [2] ae c1 [2] b9 ca [2] a2 84 [2] 9f }

  condition:
    any of them
}
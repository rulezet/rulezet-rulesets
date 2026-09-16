rule TTP_XOR_MULT_DOSStub_cca2 {
  strings:
    $key_cca2 = { 98 ca [2] ec d2 [2] ab d0 [2] ec c1 [2] a2 cd [2] ae c7 [2] b9 cc [2] a2 82 [2] 9f }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_cca3 {
  strings:
    $key_cca3 = { 98 cb [2] ec d3 [2] ab d1 [2] ec c0 [2] a2 cc [2] ae c6 [2] b9 cd [2] a2 83 [2] 9f }

  condition:
    any of them
}
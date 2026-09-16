rule TTP_XOR_MULT_DOSStub_1da2 {
  strings:
    $key_1da2 = { 49 ca [2] 3d d2 [2] 7a d0 [2] 3d c1 [2] 73 cd [2] 7f c7 [2] 68 cc [2] 73 82 [2] 4e }

  condition:
    any of them
}
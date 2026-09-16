rule TTP_XOR_MULT_DOSStub_fda2 {
  strings:
    $key_fda2 = { a9 ca [2] dd d2 [2] 9a d0 [2] dd c1 [2] 93 cd [2] 9f c7 [2] 88 cc [2] 93 82 [2] ae }

  condition:
    any of them
}
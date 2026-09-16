rule TTP_XOR_MULT_DOSStub_cda2 {
  strings:
    $key_cda2 = { 99 ca [2] ed d2 [2] aa d0 [2] ed c1 [2] a3 cd [2] af c7 [2] b8 cc [2] a3 82 [2] 9e }

  condition:
    any of them
}
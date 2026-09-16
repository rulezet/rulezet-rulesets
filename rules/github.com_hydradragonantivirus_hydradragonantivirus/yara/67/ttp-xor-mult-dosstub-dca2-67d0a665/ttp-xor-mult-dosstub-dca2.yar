rule TTP_XOR_MULT_DOSStub_dca2 {
  strings:
    $key_dca2 = { 88 ca [2] fc d2 [2] bb d0 [2] fc c1 [2] b2 cd [2] be c7 [2] a9 cc [2] b2 82 [2] 8f }

  condition:
    any of them
}
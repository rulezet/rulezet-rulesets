rule TTP_XOR_MULT_DOSStub_5380 {
  strings:
    $key_5380 = { 07 e8 [2] 73 f0 [2] 34 f2 [2] 73 e3 [2] 3d ef [2] 31 e5 [2] 26 ee [2] 3d a0 [2] 00 }

  condition:
    any of them
}
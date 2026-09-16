rule TTP_XOR_MULT_DOSStub_d008 {
  strings:
    $key_d008 = { 84 60 [2] f0 78 [2] b7 7a [2] f0 6b [2] be 67 [2] b2 6d [2] a5 66 [2] be 28 [2] 83 }

  condition:
    any of them
}
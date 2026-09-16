rule TTP_XOR_MULT_DOSStub_51aa {
  strings:
    $key_51aa = { 05 c2 [2] 71 da [2] 36 d8 [2] 71 c9 [2] 3f c5 [2] 33 cf [2] 24 c4 [2] 3f 8a [2] 02 }

  condition:
    any of them
}
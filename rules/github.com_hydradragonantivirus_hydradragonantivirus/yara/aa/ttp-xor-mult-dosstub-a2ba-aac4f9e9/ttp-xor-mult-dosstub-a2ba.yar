rule TTP_XOR_MULT_DOSStub_a2ba {
  strings:
    $key_a2ba = { f6 d2 [2] 82 ca [2] c5 c8 [2] 82 d9 [2] cc d5 [2] c0 df [2] d7 d4 [2] cc 9a [2] f1 }

  condition:
    any of them
}
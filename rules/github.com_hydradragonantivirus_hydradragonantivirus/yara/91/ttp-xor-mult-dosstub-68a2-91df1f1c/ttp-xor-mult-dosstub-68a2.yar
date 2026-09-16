rule TTP_XOR_MULT_DOSStub_68a2 {
  strings:
    $key_68a2 = { 3c ca [2] 48 d2 [2] 0f d0 [2] 48 c1 [2] 06 cd [2] 0a c7 [2] 1d cc [2] 06 82 [2] 3b }

  condition:
    any of them
}
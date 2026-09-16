rule TTP_XOR_MULT_DOSStub_5ca2 {
  strings:
    $key_5ca2 = { 08 ca [2] 7c d2 [2] 3b d0 [2] 7c c1 [2] 32 cd [2] 3e c7 [2] 29 cc [2] 32 82 [2] 0f }

  condition:
    any of them
}
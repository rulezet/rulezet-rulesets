rule TTP_XOR_MULT_DOSStub_5ca3 {
  strings:
    $key_5ca3 = { 08 cb [2] 7c d3 [2] 3b d1 [2] 7c c0 [2] 32 cc [2] 3e c6 [2] 29 cd [2] 32 83 [2] 0f }

  condition:
    any of them
}
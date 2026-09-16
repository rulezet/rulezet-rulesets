rule TTP_XOR_MULT_DOSStub_5ca5 {
  strings:
    $key_5ca5 = { 08 cd [2] 7c d5 [2] 3b d7 [2] 7c c6 [2] 32 ca [2] 3e c0 [2] 29 cb [2] 32 85 [2] 0f }

  condition:
    any of them
}
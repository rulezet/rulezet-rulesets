rule TTP_XOR_MULT_DOSStub_61a5 {
  strings:
    $key_61a5 = { 35 cd [2] 41 d5 [2] 06 d7 [2] 41 c6 [2] 0f ca [2] 03 c0 [2] 14 cb [2] 0f 85 [2] 32 }

  condition:
    any of them
}
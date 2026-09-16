rule TTP_XOR_MULT_DOSStub_05a5 {
  strings:
    $key_05a5 = { 51 cd [2] 25 d5 [2] 62 d7 [2] 25 c6 [2] 6b ca [2] 67 c0 [2] 70 cb [2] 6b 85 [2] 56 }

  condition:
    any of them
}
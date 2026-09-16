rule TTP_XOR_MULT_DOSStub_32ae {
  strings:
    $key_32ae = { 66 c6 [2] 12 de [2] 55 dc [2] 12 cd [2] 5c c1 [2] 50 cb [2] 47 c0 [2] 5c 8e [2] 61 }

  condition:
    any of them
}
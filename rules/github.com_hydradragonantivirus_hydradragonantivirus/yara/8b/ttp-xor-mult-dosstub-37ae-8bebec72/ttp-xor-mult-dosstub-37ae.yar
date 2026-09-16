rule TTP_XOR_MULT_DOSStub_37ae {
  strings:
    $key_37ae = { 63 c6 [2] 17 de [2] 50 dc [2] 17 cd [2] 59 c1 [2] 55 cb [2] 42 c0 [2] 59 8e [2] 64 }

  condition:
    any of them
}
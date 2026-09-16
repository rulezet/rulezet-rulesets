rule TTP_XOR_MULT_DOSStub_66eb {
  strings:
    $key_66eb = { 32 83 [2] 46 9b [2] 01 99 [2] 46 88 [2] 08 84 [2] 04 8e [2] 13 85 [2] 08 cb [2] 35 }

  condition:
    any of them
}
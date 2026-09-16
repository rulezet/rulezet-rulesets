rule TTP_XOR_MULT_DOSStub_1aeb {
  strings:
    $key_1aeb = { 4e 83 [2] 3a 9b [2] 7d 99 [2] 3a 88 [2] 74 84 [2] 78 8e [2] 6f 85 [2] 74 cb [2] 49 }

  condition:
    any of them
}
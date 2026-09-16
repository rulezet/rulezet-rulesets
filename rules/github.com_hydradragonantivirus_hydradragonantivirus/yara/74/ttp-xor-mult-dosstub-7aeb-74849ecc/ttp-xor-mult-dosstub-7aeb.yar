rule TTP_XOR_MULT_DOSStub_7aeb {
  strings:
    $key_7aeb = { 2e 83 [2] 5a 9b [2] 1d 99 [2] 5a 88 [2] 14 84 [2] 18 8e [2] 0f 85 [2] 14 cb [2] 29 }

  condition:
    any of them
}
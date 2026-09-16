rule TTP_XOR_MULT_DOSStub_5aeb {
  strings:
    $key_5aeb = { 0e 83 [2] 7a 9b [2] 3d 99 [2] 7a 88 [2] 34 84 [2] 38 8e [2] 2f 85 [2] 34 cb [2] 09 }

  condition:
    any of them
}
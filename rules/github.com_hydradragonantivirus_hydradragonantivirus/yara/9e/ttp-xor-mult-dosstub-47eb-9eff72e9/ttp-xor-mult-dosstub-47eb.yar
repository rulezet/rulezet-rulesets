rule TTP_XOR_MULT_DOSStub_47eb {
  strings:
    $key_47eb = { 13 83 [2] 67 9b [2] 20 99 [2] 67 88 [2] 29 84 [2] 25 8e [2] 32 85 [2] 29 cb [2] 14 }

  condition:
    any of them
}
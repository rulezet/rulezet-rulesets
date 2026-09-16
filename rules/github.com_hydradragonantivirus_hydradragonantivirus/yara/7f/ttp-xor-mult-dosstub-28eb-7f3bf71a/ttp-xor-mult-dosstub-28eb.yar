rule TTP_XOR_MULT_DOSStub_28eb {
  strings:
    $key_28eb = { 7c 83 [2] 08 9b [2] 4f 99 [2] 08 88 [2] 46 84 [2] 4a 8e [2] 5d 85 [2] 46 cb [2] 7b }

  condition:
    any of them
}
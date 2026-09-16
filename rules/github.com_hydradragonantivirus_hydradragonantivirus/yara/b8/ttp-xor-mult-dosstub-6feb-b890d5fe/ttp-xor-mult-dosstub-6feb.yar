rule TTP_XOR_MULT_DOSStub_6feb {
  strings:
    $key_6feb = { 3b 83 [2] 4f 9b [2] 08 99 [2] 4f 88 [2] 01 84 [2] 0d 8e [2] 1a 85 [2] 01 cb [2] 3c }

  condition:
    any of them
}
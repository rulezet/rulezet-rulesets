rule TTP_XOR_MULT_DOSStub_5feb {
  strings:
    $key_5feb = { 0b 83 [2] 7f 9b [2] 38 99 [2] 7f 88 [2] 31 84 [2] 3d 8e [2] 2a 85 [2] 31 cb [2] 0c }

  condition:
    any of them
}
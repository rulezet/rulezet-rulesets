rule TTP_XOR_MULT_DOSStub_00eb {
  strings:
    $key_00eb = { 54 83 [2] 20 9b [2] 67 99 [2] 20 88 [2] 6e 84 [2] 62 8e [2] 75 85 [2] 6e cb [2] 53 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_04eb {
  strings:
    $key_04eb = { 50 83 [2] 24 9b [2] 63 99 [2] 24 88 [2] 6a 84 [2] 66 8e [2] 71 85 [2] 6a cb [2] 57 }

  condition:
    any of them
}
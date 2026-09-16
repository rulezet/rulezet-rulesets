rule TTP_XOR_MULT_DOSStub_33eb {
  strings:
    $key_33eb = { 67 83 [2] 13 9b [2] 54 99 [2] 13 88 [2] 5d 84 [2] 51 8e [2] 46 85 [2] 5d cb [2] 60 }

  condition:
    any of them
}
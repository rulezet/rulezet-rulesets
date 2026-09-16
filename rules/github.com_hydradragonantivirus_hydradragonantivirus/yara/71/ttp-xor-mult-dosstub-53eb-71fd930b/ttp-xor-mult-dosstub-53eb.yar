rule TTP_XOR_MULT_DOSStub_53eb {
  strings:
    $key_53eb = { 07 83 [2] 73 9b [2] 34 99 [2] 73 88 [2] 3d 84 [2] 31 8e [2] 26 85 [2] 3d cb [2] 00 }

  condition:
    any of them
}
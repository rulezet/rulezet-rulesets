rule TTP_XOR_MULT_DOSStub_e3eb {
  strings:
    $key_e3eb = { b7 83 [2] c3 9b [2] 84 99 [2] c3 88 [2] 8d 84 [2] 81 8e [2] 96 85 [2] 8d cb [2] b0 }

  condition:
    any of them
}
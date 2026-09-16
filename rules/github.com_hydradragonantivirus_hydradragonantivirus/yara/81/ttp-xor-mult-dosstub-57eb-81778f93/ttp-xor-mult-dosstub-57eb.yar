rule TTP_XOR_MULT_DOSStub_57eb {
  strings:
    $key_57eb = { 03 83 [2] 77 9b [2] 30 99 [2] 77 88 [2] 39 84 [2] 35 8e [2] 22 85 [2] 39 cb [2] 04 }

  condition:
    any of them
}
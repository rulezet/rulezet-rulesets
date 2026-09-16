rule TTP_XOR_MULT_DOSStub_0aeb {
  strings:
    $key_0aeb = { 5e 83 [2] 2a 9b [2] 6d 99 [2] 2a 88 [2] 64 84 [2] 68 8e [2] 7f 85 [2] 64 cb [2] 59 }

  condition:
    any of them
}
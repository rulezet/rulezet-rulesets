rule TTP_XOR_MULT_DOSStub_6aeb {
  strings:
    $key_6aeb = { 3e 83 [2] 4a 9b [2] 0d 99 [2] 4a 88 [2] 04 84 [2] 08 8e [2] 1f 85 [2] 04 cb [2] 39 }

  condition:
    any of them
}
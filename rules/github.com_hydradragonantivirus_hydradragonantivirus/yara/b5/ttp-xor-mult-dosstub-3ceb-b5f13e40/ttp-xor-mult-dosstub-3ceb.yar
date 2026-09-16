rule TTP_XOR_MULT_DOSStub_3ceb {
  strings:
    $key_3ceb = { 68 83 [2] 1c 9b [2] 5b 99 [2] 1c 88 [2] 52 84 [2] 5e 8e [2] 49 85 [2] 52 cb [2] 6f }

  condition:
    any of them
}
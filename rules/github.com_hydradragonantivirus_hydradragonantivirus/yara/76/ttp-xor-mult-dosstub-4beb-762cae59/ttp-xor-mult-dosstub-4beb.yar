rule TTP_XOR_MULT_DOSStub_4beb {
  strings:
    $key_4beb = { 1f 83 [2] 6b 9b [2] 2c 99 [2] 6b 88 [2] 25 84 [2] 29 8e [2] 3e 85 [2] 25 cb [2] 18 }

  condition:
    any of them
}
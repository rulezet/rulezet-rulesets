rule TTP_XOR_MULT_DOSStub_2b7b {
  strings:
    $key_2b7b = { 7f 13 [2] 0b 0b [2] 4c 09 [2] 0b 18 [2] 45 14 [2] 49 1e [2] 5e 15 [2] 45 5b [2] 78 }

  condition:
    any of them
}